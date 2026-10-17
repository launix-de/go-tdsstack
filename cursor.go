/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
)

const tdsCursorLimit = 32
const tdsCursorBytesLimit = 16 << 20
const tdsCursorRowsLimit = 100000
const tdsCursorFetchLimit = 10000

type cursorSnapshot struct {
	columns               []Column
	rows                  [][]any
	bytes, start, fetched int
	name                  string
}

func cursorInteger(a tdsRPCParameter, output, nullable bool) int32 {
	flags := byte(0)
	if output {
		flags = 1
	}
	if a.flags != flags {
		panic("invalid cursor parameter flags")
	}
	if a.value == nil && nullable {
		return 0
	}
	n, ok := a.value.(int64)
	if !ok || n < math.MinInt32 || n > math.MaxInt32 {
		panic("invalid cursor integer")
	}
	return int32(n)
}
func (c *connection) removeCursor(handle int32) {
	if x, ok := c.cursors[handle]; ok {
		c.cursorBytes -= x.bytes
		delete(c.cursors, handle)
	}
}

// snapshotWriter owns native decoded payloads only. Each stored row is cloned
// and prevalidated; it never retains application codecs or invocation state.
type snapshotWriter struct {
	output       *resultWriter
	columns      []Column
	rows         [][]any
	bytes        int
	fields, done bool
	ctx          context.Context
}

// Information belongs to this invocation's response, never the retained
// cursor snapshot. Fetches replay only cloned fields and rows.
func (s *snapshotWriter) Message(d Diagnostic) error {
	if s.done {
		return fmt.Errorf("cursor result already completed")
	}
	if s.output == nil {
		return fmt.Errorf("cursor information output unavailable")
	}
	return s.output.Message(d)
}

func (s *snapshotWriter) Fields(columns []Column) error {
	if s.fields || s.done || len(columns) > 254 {
		return fmt.Errorf("cursor requires one bounded result set")
	}
	for _, c := range columns {
		if !validType(c.WireType) {
			return fmt.Errorf("invalid cursor wire descriptor")
		}
		s.bytes += 64 + len(c.Name)
	}
	s.columns = append([]Column(nil), columns...)
	s.fields = true
	return nil
}
func (s *snapshotWriter) Row(row []any) error {
	if !s.fields || s.done || len(row) != len(s.columns) {
		return fmt.Errorf("invalid cursor row")
	}
	if e := s.ctx.Err(); e != nil {
		return e
	}
	if len(s.rows) >= tdsCursorRowsLimit {
		return fmt.Errorf("cursor row limit")
	}
	clone := make([]any, len(row))
	size := 24 + 16*len(row)
	err := catchWire(func() {
		for i, v := range row {
			encoded := encodeWireValue(s.columns[i], v)
			size += len(encoded)
			switch x := v.(type) {
			case []byte:
				clone[i] = append([]byte(nil), x...)
			case string:
				clone[i] = strings.Clone(x)
			case Decimal:
				clone[i] = Decimal{strings.Clone(x.Coefficient)}
			default:
				clone[i] = v
			}
		}
	})
	if err != nil {
		return err
	}
	if size > tdsCursorBytesLimit-s.bytes {
		return fmt.Errorf("cursor snapshot memory limit")
	}
	s.bytes += size
	s.rows = append(s.rows, clone)
	return nil
}
func (s *snapshotWriter) Done(c Completion) error {
	if c.More || s.done {
		return fmt.Errorf("cursor requires one result set")
	}
	s.done = true
	return nil
}
func (c *connection) openCursor(r tdsRPC, state *requestState, response *tdsResponse) (*cursorSnapshot, int32) {
	a := r.arguments
	if len(a) < 5 || c.server.Handler.Describe == nil {
		panic("cursor requires pure describe")
	}
	if len(c.cursors) >= tdsCursorLimit || c.cursorBytes >= tdsCursorBytesLimit || c.nextCursor == math.MaxInt32 {
		panic("cursor resource limit")
	}
	if cursorInteger(a[0], true, true) != 0 {
		panic("cursor handle must be unassigned")
	}
	scroll := cursorInteger(a[2], true, false)
	if scroll != 8 && scroll != 0x1008 {
		panic("only STATIC cursors supported")
	}
	concurrency := cursorInteger(a[3], true, false)
	if concurrency != 1 && concurrency != 0x2001 {
		panic("only READ_ONLY cursors supported")
	}
	cursorInteger(a[4], true, true)
	q := Request{Database: c.database, Text: rpcText(a[1], false), Cursor: true}
	if scroll == 0x1008 && len(a) < 6 {
		panic("missing cursor declarations")
	}
	if len(a) > 5 {
		q.Declarations = rpcText(a[5], true)
		q.Parameters = rpcParameters(r, 6)
	}
	for _, p := range q.Parameters {
		if p.Flags != 0 {
			panic("cursor output parameters unsupported")
		}
	}
	// Application validates the shape and purity. The library never parses SELECT.
	if _, err := c.server.Handler.Describe(state.ctx, c.session, q); err != nil {
		panic(err)
	}
	sink := &snapshotWriter{ctx: state.ctx, output: &resultWriter{ctx: state.ctx, w: response}}
	if err := c.server.Handler.Execute(state.ctx, c.session, q, sink); err != nil {
		panic(err)
	}
	if sink.output.err != nil {
		panic(sink.output.err)
	}
	if err := state.ctx.Err(); err != nil {
		panic(err)
	}
	if !sink.fields {
		panic("cursor query returned no fields")
	}
	if sink.bytes > tdsCursorBytesLimit-c.cursorBytes {
		panic("cursor connection memory limit")
	}
	c.nextCursor++
	return &cursorSnapshot{columns: sink.columns, rows: sink.rows, bytes: sink.bytes}, c.nextCursor
}
func (cursor *cursorSnapshot) rangeForFetch(kind, rownum, nrows int32) (start, end, position int, status uint32) {
	count, n := len(cursor.rows), int(nrows)
	if n < 0 || n > tdsCursorFetchLimit || (n == 0 && kind != 1 && kind != 8) {
		panic("invalid or excessive TDS cursor fetch size")
	}
	position = cursor.start
	switch kind {
	case 1:
		position = 1
		if n == 0 {
			return 0, 0, 0, 0
		}
	case 2:
		position += cursor.fetched
		if position == 0 {
			position = 1
		}
	case 4:
		position -= n
		if position < 1 && cursor.start > 0 {
			position, status = 1, 2
		}
	case 8:
		position = count - n + 1
		if n == 0 {
			return 0, 0, count + 1, 0
		}
		if position < 1 {
			position = 1
		}
	case 16:
		position = int(rownum)
		if position < 0 {
			position += count + 1
		}
	case 32:
		position += int(rownum)
	default:
		panic("unsupported TDS cursor fetch mode")
	}
	if position <= 0 {
		return 0, 0, 0, status
	}
	if position > count {
		return count, count, count + 1, status
	}
	start = position - 1
	end = start + n
	if end > count {
		end = count
	}
	return
}

func (c *connection) cursorRPC(rpc tdsRPC, request *requestState, response *tdsResponse) (err error) {
	var tokens bytes.Buffer
	var openedHandle int32
	completed := false
	defer func() {
		if openedHandle != 0 && !completed {
			c.removeCursor(openedHandle)
		}
	}()
	status := uint32(0)
	info := false
	var positionCursor *cursorSnapshot
	position, fetched := 0, 0
	switch rpc.procedure {
	case 2:
		cursor, handle := c.openCursor(rpc, request, response)
		if c.cursors == nil {
			c.cursors = make(map[int32]*cursorSnapshot)
		}
		c.cursors[handle] = cursor
		c.cursorBytes += cursor.bytes
		openedHandle = handle
		sink := &resultWriter{w: response, columns: cursor.wireColumns(), browseMetadata: c.browseMetadata}
		sink.fields = true
		sink.publish()
		tdsDone(&tokens, 0xff, 1, 0)
		tokens.WriteByte(0x79)
		tdsU32(&tokens, 0)
		for _, output := range []struct {
			ordinal uint16
			value   int32
		}{{0, handle}, {2, 8}, {3, 1}, {4, int32(len(cursor.rows))}} {
			tdsReturnInteger(&tokens, rpc.arguments[output.ordinal].name, output.ordinal, output.value)
		}
	case 8:
		if len(rpc.arguments) != 3 {
			panic("cursor option requires handle, code and value")
		}
		handle := rpcHandle(rpc.arguments[0])
		cursor, found := c.cursors[handle]
		if !found {
			panic("unknown TDS cursor handle")
		}
		code := cursorInteger(rpc.arguments[1], false, false)
		switch code {
		case 2:
			name := rpcText(rpc.arguments[2], false)
			if len(name) > 512 || len(tdsUTF16(name)) > 256 {
				panic("TDS cursor name exceeds 128 characters")
			}
			for id, candidate := range c.cursors {
				if name != "" && id != handle && strings.EqualFold(candidate.name, name) {
					panic("duplicate TDS cursor name")
				}
			}
			oldSize, newSize := 0, 0
			if cursor.name != "" {
				oldSize = 16 + (len(cursor.name)+7)&^7
			}
			if name != "" {
				newSize = 16 + (len(name)+7)&^7
			}
			if c.cursorBytes+newSize-oldSize > tdsCursorBytesLimit {
				panic("TDS cursor memory limit exceeded")
			}
			cursor.name = strings.Clone(name)
			cursor.bytes += newSize - oldSize
			c.cursorBytes += newSize - oldSize
		case 3:
			column := cursorInteger(rpc.arguments[2], false, false)
			if column < 0 || int(column) > len(cursor.columns) {
				panic("invalid TDS cursor TEXTDATA column")
			}
			// Snapshots always return scalar data; text pointers are unsupported.
		case 4, 5, 6:
			cursorInteger(rpc.arguments[2], true, true)
			value := int32(8)
			if code == 5 {
				value = 1
			}
			if code == 6 {
				value = int32(len(cursor.rows))
			}
			tokens.WriteByte(0x79)
			tdsU32(&tokens, 0)
			tdsReturnInteger(&tokens, rpc.arguments[2].name, 2, value)
			info = true
		default:
			panic("unsupported TDS cursor option")
		}
		if !info {
			tokens.WriteByte(0x79)
			tdsU32(&tokens, 0)
		}
	case 7, 9:
		if len(rpc.arguments) == 0 {
			panic("missing TDS cursor handle")
		}
		handle := rpcHandle(rpc.arguments[0])
		cursor, found := c.cursors[handle]
		if !found {
			panic("unknown TDS cursor handle")
		}
		if rpc.procedure == 9 {
			if len(rpc.arguments) != 1 {
				panic("cursor close requires exactly one handle")
			}
			c.removeCursor(handle)
		} else {
			if len(rpc.arguments) > 4 {
				panic("too many cursor fetch parameters")
			}
			kind, rownum, nrows := int32(2), int32(0), int32(20)
			if len(rpc.arguments) > 1 {
				kind = cursorInteger(rpc.arguments[1], false, false)
			}
			if kind == 256 {
				info = true
				if len(rpc.arguments) != 4 {
					panic("cursor INFO requires rownum/nrows outputs")
				}
				cursorInteger(rpc.arguments[2], true, true)
				cursorInteger(rpc.arguments[3], true, true)
				rownum = int32(cursor.start)
				if cursor.start > len(cursor.rows) {
					rownum = -1
				}
				tokens.WriteByte(0x79)
				tdsU32(&tokens, 0)
				tdsReturnInteger(&tokens, rpc.arguments[2].name, 2, rownum)
				tdsReturnInteger(&tokens, rpc.arguments[3].name, 3, int32(len(cursor.rows)))
				break
			}
			if len(rpc.arguments) > 2 {
				rownum = cursorInteger(rpc.arguments[2], false, kind == 1 || kind == 2 || kind == 4 || kind == 8)
			}
			if len(rpc.arguments) > 3 {
				nrows = cursorInteger(rpc.arguments[3], false, false)
			}
			start, end, next, fetchStatus := cursor.rangeForFetch(kind, rownum, nrows)
			positionCursor, position, fetched, status = cursor, next, end-start, fetchStatus
			sink := &resultWriter{w: response, columns: cursor.wireColumns(), browseMetadata: c.browseMetadata}
			if rpc.options&2 != 0 {
				// The cursor's immutable schema was already advertised by open.
				sink.write([]byte{0x81, 255, 255})
				sink.fields = true
			} else {
				sink.fields = true
				sink.publish()
			}
			for _, row := range cursor.rows[start:end] {
				if err := request.ctx.Err(); err != nil {
					panic(err)
				}
				values := append(append([]any(nil), row...), int64(1))
				if err = sink.Row(values); err != nil {
					return err
				}
			}
			tdsDone(&tokens, 0xfd, 1, 0)
		}
		if !info {
			tokens.WriteByte(0x79)
			tdsU32(&tokens, status)
		}
	}
	if request.finish() {
		tokens.Reset()
		tdsDone(&tokens, 0xfd, 0x20, 0)
	} else {
		tdsDone(&tokens, 0xfe, 0, 0)
	}
	if _, err = response.Write(tokens.Bytes()); err != nil {
		return err
	}
	err = response.flush(true)
	if err == nil && request.ctx.Err() == nil {
		completed = true
		if positionCursor != nil {
			positionCursor.start, positionCursor.fetched = position, fetched
		}
	}
	return
}

func (cursor *cursorSnapshot) wireColumns() []Column {
	columns := append([]Column(nil), cursor.columns...)
	for i := range columns {
		columns[i].Flags &^= 4 // implemented cursors are static read-only snapshots
		columns[i].Source = [4]string{}
		columns[i].Key = false
	}
	return append(columns, Column{Name: "rowstat", WireType: WireType{Kind: 0x26, Size: 4}, Flags: 0x2000})
}
