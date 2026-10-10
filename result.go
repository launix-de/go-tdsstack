/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"unicode/utf8"
)

type tdsColumn = Column

func isInt64(v any) bool { _, ok := v.(int64); return ok }
func catchWire(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("wire encoding: %v", r)
		}
	}()
	fn()
	return
}
func validType(t WireType) bool {
	switch t.Kind {
	case 0x26:
		return t.Size == 1 || t.Size == 2 || t.Size == 4 || t.Size == 8
	case 0x68:
		return t.Size == 1
	case 0x6d, 0x6e, 0x6f:
		return t.Size == 4 || t.Size == 8
	case 0x6a, 0x6c:
		return t.Precision >= 1 && t.Precision <= 38 && t.Scale <= t.Precision && t.Size == tdsDecimalSize(int(t.Precision))
	case 0x28:
		return true
	case 0x29, 0x2a, 0x2b:
		return t.Scale <= 7
	case 0xe7, 0xef, 0xa7, 0xaf, 0xa5, 0xad:
		return t.Size > 0 && t.Size <= 65535
	}
	return false
}

type resultWriter struct {
	active         func() bool
	mu             sync.Mutex
	w              io.Writer
	ctx            context.Context
	columns        []Column
	fields, done   bool
	count          uint64
	browseMetadata bool
	rpc            bool
	completion     func(Completion) error
	err            error
}

func (r *resultWriter) Fields(columns []Column) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.fields && !r.done {
		return fmt.Errorf("fields must be declared exactly once before rows")
	}
	if len(columns) > 65534 {
		return fmt.Errorf("too many result columns")
	}
	r.columns = append([]Column(nil), columns...)
	r.browseMetadata = false
	for _, c := range r.columns {
		if c.Browse {
			r.browseMetadata = true
		}
		if !validType(c.WireType) {
			return fmt.Errorf("invalid explicit wire descriptor for %s", c.Name)
		}
	}
	r.fields = true
	r.done = false
	r.count = 0
	r.err = catchWire(func() { r.publish() })
	return r.err
}
func (r *resultWriter) write(data []byte) {
	if err := tdsWriteAll(r.w, data); err != nil {
		panic(err)
	}
}
func (r *resultWriter) publish() {
	var metadata bytes.Buffer
	metadata.WriteByte(0x81)
	tdsU16(&metadata, uint16(len(r.columns)))
	for i := range r.columns {
		col := &r.columns[i]
		tdsU32(&metadata, col.UserType)
		tdsU16(&metadata, col.Flags)
		metadata.WriteByte(col.Kind)
		switch col.Kind {
		case 0x26, 0x6d:
			size := col.Size
			metadata.WriteByte(byte(size))
		case 0x68:
			metadata.WriteByte(1)
		case 0x6a, 0x6c:
			metadata.Write([]byte{byte(col.Size), col.Precision, col.Scale})
		case 0x6e:
			metadata.WriteByte(byte(col.Size))
		case 0x6f:
			metadata.WriteByte(byte(col.Size))
		case 0x28:
		case 0x29, 0x2a, 0x2b:
			metadata.WriteByte(col.Scale)
		case 0xa5, 0xad:
			size := col.Size
			tdsU16(&metadata, uint16(size))
		case 0xe7, 0xef, 0xa7, 0xaf:
			size := col.Size
			tdsU16(&metadata, uint16(size)) // NVARCHAR(MAX), PLP values
			metadata.Write(col.Collation[:])
		}
		tdsBText(&metadata, col.Name)
	}
	if r.browseMetadata {
		if len(r.columns) > 255 {
			panic("too many browse result columns")
		}
		var tableNames, info bytes.Buffer
		tables := make(map[[3]string]byte)
		for _, column := range r.columns {
			if column.Source[2] == "" {
				continue
			}
			table := [3]string{column.Source[0], column.Source[1], column.Source[2]}
			if tables[table] != 0 {
				continue
			}
			if len(tables) == 255 {
				panic("too many browse source tables")
			}
			tables[table] = byte(len(tables) + 1)
			tableNames.WriteByte(3)
			for _, part := range []string{table[0], table[1], table[2]} {
				encoded := tdsUTF16(part)
				if len(encoded)/2 > 65535 {
					panic("browse source name exceeds protocol bounds")
				}
				tdsU16(&tableNames, uint16(len(encoded)/2))
				tableNames.Write(encoded)
			}
		}
		for i, column := range r.columns {
			flags := byte(4) // expression: no proven base-column provenance
			table := tables[[3]string{column.Source[0], column.Source[1], column.Source[2]}]
			if table != 0 {
				flags = 0
				if column.Key {
					flags |= 0x08
				}
				if column.Name != column.Source[3] {
					flags |= 0x20
				}
			}
			if column.Flags&0x2000 != 0 {
				flags |= 0x10
			}
			info.Write([]byte{byte(i + 1), table, flags})
			if flags&0x20 != 0 {
				tdsBText(&info, column.Source[3])
			}
		}
		if tableNames.Len() > 65535 || info.Len() > 65535 {
			panic("browse metadata exceeds protocol bounds")
		}
		if tableNames.Len() != 0 {
			tdsToken(&metadata, 0xa4, tableNames.Bytes())
		}
		tdsToken(&metadata, 0xa5, info.Bytes())
	}
	r.write(metadata.Bytes())
}
func encodeWireValue(col Column, value any) []byte {
	kind := col.Kind
	if kind == 0x6a || kind == 0x6c || kind == 0x6e {
		return tdsEncodeNumeric(col, value)
	}
	if kind == 0x28 || kind == 0x29 || kind == 0x2a || kind == 0x2b || kind == 0x6f {
		return tdsEncodeTemporal(col, value)
	}
	var b bytes.Buffer
	switch kind {
	case 0x26, 0x68, 0x6d:
		if value == nil {
			return []byte{0}
		}
		b.WriteByte(byte(col.Size))
		switch kind {
		case 0x26:
			n, ok := value.(int64)
			if !ok {
				panic("integer wire value requires int64")
			}
			if col.Size == 1 && (n < 0 || n > 255) || col.Size == 2 && (n < math.MinInt16 || n > math.MaxInt16) || col.Size == 4 && (n < math.MinInt32 || n > math.MaxInt32) {
				panic("integer wire width overflow")
			}
			var data [8]byte
			binary.LittleEndian.PutUint64(data[:], uint64(n))
			b.Write(data[:col.Size])
		case 0x68:
			n, ok := value.(bool)
			if !ok {
				panic("bit wire value requires bool")
			}
			if n {
				b.WriteByte(1)
			} else {
				b.WriteByte(0)
			}
		case 0x6d:
			n, ok := value.(float64)
			if !ok {
				panic("float wire value requires float64")
			}
			if col.Size == 4 {
				tdsU32(&b, math.Float32bits(float32(n)))
			} else {
				tdsU64(&b, math.Float64bits(n))
			}
		}
	case 0xe7, 0xef, 0xa7, 0xaf, 0xa5, 0xad:
		if value == nil {
			if col.Size == 65535 {
				tdsU64(&b, math.MaxUint64)
			} else {
				tdsU16(&b, 65535)
			}
			return b.Bytes()
		}
		var data []byte
		if kind == 0xa5 || kind == 0xad {
			var ok bool
			data, ok = value.([]byte)
			if !ok {
				panic("binary wire value requires bytes")
			}
		} else {
			text, ok := value.(string)
			if !ok || !utf8.ValidString(text) {
				panic("character wire value requires valid text")
			}
			if kind == 0xe7 || kind == 0xef {
				data = tdsUTF16(text)
			} else if binary.LittleEndian.Uint32(col.Collation[:])&(1<<26) != 0 {
				data = []byte(text)
			} else {
				var err error
				data, err = tdsCP1252.NewEncoder().Bytes([]byte(text))
				if err != nil {
					panic(err)
				}
			}
		}
		if len(data) > tdsMaxValue || col.Size != 65535 && len(data) > col.Size {
			panic("character/binary wire width overflow")
		}
		if col.Size == 65535 {
			tdsU64(&b, uint64(len(data)))
			if len(data) != 0 {
				tdsU32(&b, uint32(len(data)))
				b.Write(data)
			}
			tdsU32(&b, 0)
		} else {
			tdsU16(&b, uint16(len(data)))
			b.Write(data)
		}
	default:
		panic("unsupported wire descriptor")
	}
	return b.Bytes()
}
func (r *resultWriter) Row(values []any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if !r.fields || r.done {
		return fmt.Errorf("row requires declared fields")
	}
	if len(values) != len(r.columns) {
		return fmt.Errorf("row width differs from fields")
	}
	if r.ctx != nil {
		if err := r.ctx.Err(); err != nil {
			return err
		}
	}
	// Assemble one fully validated row before writing any token, preserving framing
	// if a frontend supplies a wrong wire payload.
	r.err = catchWire(func() {
		var row bytes.Buffer
		row.WriteByte(0xd1)
		for i, v := range values {
			row.Write(encodeWireValue(r.columns[i], v))
		}
		r.write(row.Bytes())
	})
	if r.err == nil {
		r.count++
	}
	return r.err
}
func (r *resultWriter) Done(c Completion) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.done {
		return fmt.Errorf("result already completed")
	}
	if r.completion != nil {
		if err := r.completion(c); err != nil {
			return err
		}
	}
	status := uint16(0)
	if r.active != nil && r.active() {
		status |= 4
	}
	if c.More || r.rpc {
		status |= 1
	}
	if !c.NoCount {
		status |= 0x10
	}
	var b bytes.Buffer
	token := byte(0xfd)
	if r.rpc {
		token = 0xff
	}
	tdsDone(&b, token, status, c.Rows)
	r.err = tdsWriteAll(r.w, b.Bytes())
	r.done = true
	r.fields = false
	r.columns = nil
	return r.err
}
