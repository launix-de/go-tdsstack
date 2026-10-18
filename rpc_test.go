/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func rawClient(t *testing.T, dsn string) net.Conn {
	t.Helper()
	values := map[string]string{}
	for _, p := range strings.Split(dsn, ";") {
		k, v, ok := strings.Cut(p, "=")
		if ok {
			values[k] = v
		}
	}
	c, e := net.Dial("tcp", net.JoinHostPort(values["server"], values["port"]))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if e = writeTDSMessage(c, 0x12, []byte{1, 0, 6, 0, 1, 255, 2}); e != nil {
		t.Fatal(e)
	}
	if _, e = readTDSMessage(c); e != nil {
		t.Fatal(e)
	}
	data := make([]byte, 94)
	binary.LittleEndian.PutUint32(data[4:], 0x74000004)
	for _, v := range []struct {
		index    int
		text     string
		password bool
	}{{40, "alice", false}, {44, "secret", true}, {68, "fixture", false}} {
		text := tdsUTF16(v.text)
		if v.password {
			for i, b := range text {
				text[i] = (b<<4 | b>>4) ^ 0xa5
			}
		}
		binary.LittleEndian.PutUint16(data[v.index:], uint16(len(data)))
		binary.LittleEndian.PutUint16(data[v.index+2:], uint16(len(text)/2))
		data = append(data, text...)
	}
	binary.LittleEndian.PutUint32(data, uint32(len(data)))
	if e = writeTDSMessage(c, 0x10, data); e != nil {
		t.Fatal(e)
	}
	if _, e = readTDSMessage(c); e != nil {
		t.Fatal(e)
	}
	return c
}
func exchange(t *testing.T, c net.Conn, id uint16, p ...Parameter) []byte {
	t.Helper()
	if e := writeTDSMessage(c, 3, encodeRPC(id, p...)); e != nil {
		t.Fatal(e)
	}
	m, e := readTDSMessage(c)
	if e != nil {
		t.Fatal(e)
	}
	return m.data
}
func intParam(name string, n int64, output bool) Parameter {
	flags := byte(0)
	if output {
		flags = 1
	}
	return Parameter{Name: name, Flags: flags, Type: WireType{Kind: 0x26, Size: 4}, Value: n}
}
func textParam(text string) Parameter {
	return Parameter{Type: WireType{Kind: 0xe7, Size: 65535}, Value: text}
}
func returnInt(data []byte, name string, ordinal uint16) (int32, bool) {
	var prefix bytes.Buffer
	prefix.WriteByte(0xac)
	tdsU16(&prefix, ordinal)
	tdsBText(&prefix, name)
	prefix.WriteByte(1)
	tdsU32(&prefix, 0)
	tdsU16(&prefix, 0)
	prefix.Write([]byte{0x26, 4, 4})
	at := bytes.Index(data, prefix.Bytes())
	if at < 0 || at+prefix.Len()+4 > len(data) {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(data[at+prefix.Len():])), true
}
func rowIntPattern(n int64, cursor bool) []byte {
	var b bytes.Buffer
	b.WriteByte(0xd1)
	b.Write(encodeWireValue(fixtureColumn("v", 0x26, 8), n))
	if cursor {
		b.Write(encodeWireValue(fixtureColumn("rowstat", 0x26, 4), int64(1)))
	}
	return b.Bytes()
}
func TestPreparedWireLifecycleAndPureDescribe(t *testing.T) {
	var executions, descriptions atomic.Int64
	_, dsn, _ := startClient(t, false, func(s *Server) {
		describe := s.Handler.Describe
		execute := s.Handler.Execute
		s.Handler.Describe = func(ctx context.Context, session Session, r Request) ([]Column, error) {
			descriptions.Add(1)
			return describe(ctx, session, r)
		}
		s.Handler.Execute = func(ctx context.Context, session Session, r Request, w ResultWriter) error {
			executions.Add(1)
			return execute(ctx, session, r, w)
		}
	})
	c := rawClient(t, dsn)
	data := exchange(t, c, 11, intParam("handle", 0, true), textParam("@v bigint"), textParam("SELECT parameter"), intParam("", 1, false))
	handle, ok := returnInt(data, "handle", 0)
	if !ok || handle <= 0 || executions.Load() != 0 || descriptions.Load() != 1 {
		t.Fatal(handle, ok, executions.Load(), descriptions.Load(), fmt.Sprintf("%x", data))
	}
	data = exchange(t, c, 12, intParam("", int64(handle), false), intParam("@v", 42, false))
	if !bytes.Contains(data, rowIntPattern(42, false)) {
		t.Fatal("prepared value", fmt.Sprintf("%x", data))
	}
	exchange(t, c, 15, intParam("", int64(handle), false))
	data = exchange(t, c, 12, intParam("", int64(handle), false), intParam("@v", 42, false))
	if !bytes.Contains(data, tdsUTF16("unknown prepared handle")) {
		t.Fatal("unprepare did not invalidate")
	}
	data = exchange(t, c, 11, intParam("bad", 0, true), textParam(""), textParam("SELECT forbidden"))
	if _, ok = returnInt(data, "bad", 0); ok || executions.Load() != 1 {
		t.Fatal("failed pure describe published handle or executed")
	}
	data = exchange(t, c, 13, intParam("execute", 0, true), textParam("@v bigint"), textParam("SELECT parameter"), intParam("@v", 77, false))
	handle, ok = returnInt(data, "execute", 0)
	if !ok || !bytes.Contains(data, rowIntPattern(77, false)) {
		t.Fatal("prepare execute")
	}
	exchange(t, c, 15, intParam("", int64(handle), false))
}
func TestStaticCursorWireOpenFetchInfoClose(t *testing.T) {
	_, dsn, _ := startClient(t, false)
	c := rawClient(t, dsn)
	data := exchange(t, c, 2, intParam("cursor", 0, true), textParam("SELECT many"), intParam("scroll", 8, true), intParam("concurrency", 1, true), intParam("count", 0, true))
	handle, ok := returnInt(data, "cursor", 0)
	if !ok || handle <= 0 {
		t.Fatal("cursor handle", fmt.Sprintf("%x", data))
	}
	count, ok := returnInt(data, "count", 4)
	if !ok || count != 400 {
		t.Fatal(count, ok)
	}
	for _, fixture := range []struct{ mode, row, n, want int64 }{{1, 0, 3, 0}, {2, 0, 2, 3}, {16, 399, 2, 398}, {8, 0, 2, 398}, {4, 0, 2, 396}} {
		data = exchange(t, c, 7, intParam("", int64(handle), false), intParam("", fixture.mode, false), intParam("", fixture.row, false), intParam("", fixture.n, false))
		if !bytes.Contains(data, rowIntPattern(fixture.want, true)) {
			t.Fatal(fixture, fmt.Sprintf("%x", data))
		}
	}
	data = exchange(t, c, 7, intParam("", int64(handle), false), intParam("", 256, false), intParam("position", 0, true), intParam("total", 0, true))
	position, ok := returnInt(data, "position", 2)
	count, ok2 := returnInt(data, "total", 3)
	if !ok || !ok2 || position != 397 || count != 400 {
		t.Fatal(position, count, ok, ok2)
	}
	exchange(t, c, 9, intParam("", int64(handle), false))
	data = exchange(t, c, 7, intParam("", int64(handle), false))
	if !bytes.Contains(data, tdsUTF16("unknown TDS cursor handle")) {
		t.Fatal("closed cursor retained")
	}
}
func TestTransactionManagerSuccessorActions(t *testing.T) {
	actions := make(chan TransactionAction, 8)
	_, dsn, _ := startClient(t, false, func(s *Server) {
		s.Handler.Transaction = func(_ context.Context, _ Session, r TransactionRequest) (Completion, error) {
			actions <- r.Action
			state := TransactionStarted
			if r.Action == Commit {
				state = TransactionCommitted
			}
			if r.Action == Rollback {
				state = TransactionRolledBack
			}
			return Completion{Transaction: state}, nil
		}
	})
	c := rawClient(t, dsn)
	send := func(tx uint64, payload []byte) []byte {
		data := append(allHeaders(tx), payload...)
		if e := writeTDSMessage(c, 14, data); e != nil {
			t.Fatal(e)
		}
		m, e := readTDSMessage(c)
		if e != nil {
			t.Fatal(e)
		}
		return m.data
	}
	data := send(0, []byte{5, 0, 2, 0})
	at := bytes.Index(data, []byte{0xe3, 11, 0, 8, 8})
	if at < 0 {
		t.Fatal("begin environment", fmt.Sprintf("%x", data))
	}
	transaction := binary.LittleEndian.Uint64(data[at+5:])
	data = send(transaction, []byte{7, 0, 0, 1, 2, 0})
	if !bytes.Contains(data, []byte{0xe3, 11, 0, 9, 0, 8}) || !bytes.Contains(data, []byte{0xe3, 11, 0, 8, 8}) {
		t.Fatal("successor environments", fmt.Sprintf("%x", data))
	}
	for _, want := range []TransactionAction{Begin, Commit, Begin} {
		select {
		case action := <-actions:
			if action != want {
				t.Fatal(action, want)
			}
		default:
			t.Fatal("missing action")
		}
	}
}
func TestCursorRejectsMutableApplicationPayloadReuse(t *testing.T) {
	s := &snapshotWriter{ctx: context.Background()}
	column := Column{Name: "b", WireType: WireType{Kind: 0xa5, Size: 8}}
	if e := s.Fields([]Column{column}); e != nil {
		t.Fatal(e)
	}
	payload := []byte{1, 2, 3}
	if e := s.Row([]any{payload}); e != nil {
		t.Fatal(e)
	}
	payload[0] = 9
	if s.rows[0][0].([]byte)[0] != 1 {
		t.Fatal("snapshot borrowed mutable row")
	}
}

func TestAttentionDuringPurePrepareDoesNotPublishHandle(t *testing.T) {
	entered := make(chan struct{})
	_, dsn, _ := startClient(t, false, func(s *Server) {
		describe := s.Handler.Describe
		s.Handler.Describe = func(ctx context.Context, session Session, r Request) ([]Column, error) {
			if r.Text == "SELECT waiting describe" {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return describe(ctx, session, r)
		}
	})
	c := rawClient(t, dsn)
	if e := writeTDSMessage(c, 3, encodeRPC(11, intParam("handle", 0, true), textParam(""), textParam("SELECT waiting describe"))); e != nil {
		t.Fatal(e)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("describe not entered")
	}
	if e := writeTDSMessage(c, 6, nil); e != nil {
		t.Fatal(e)
	}
	m, e := readTDSMessage(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := returnInt(m.data, "handle", 0); ok || !bytes.Contains(m.data, []byte{0xfd, 0x20, 0}) {
		t.Fatal("cancelled prepare published handle", fmt.Sprintf("%x", m.data))
	}
	data := exchange(t, c, 11, intParam("handle", 0, true), textParam(""), textParam("SELECT 1"))
	if handle, ok := returnInt(data, "handle", 0); !ok || handle != 1 {
		t.Fatal("cancelled prepare consumed handle", handle, ok)
	}
}
func TestFailedTransactionCompletionDoesNotBeginSuccessor(t *testing.T) {
	actions := make(chan TransactionAction, 4)
	_, dsn, _ := startClient(t, false, func(s *Server) {
		s.Handler.Transaction = func(_ context.Context, _ Session, r TransactionRequest) (Completion, error) {
			actions <- r.Action
			if r.Action == Commit {
				return Completion{}, fmt.Errorf("completion failed")
			}
			return Completion{Transaction: TransactionStarted}, nil
		}
	})
	c := rawClient(t, dsn)
	send := func(tx uint64, payload []byte) []byte {
		if e := writeTDSMessage(c, 14, append(allHeaders(tx), payload...)); e != nil {
			t.Fatal(e)
		}
		m, e := readTDSMessage(c)
		if e != nil {
			t.Fatal(e)
		}
		return m.data
	}
	data := send(0, []byte{5, 0, 2, 0})
	at := bytes.Index(data, []byte{0xe3, 11, 0, 8, 8})
	if at < 0 {
		t.Fatal("missing begin")
	}
	tx := binary.LittleEndian.Uint64(data[at+5:])
	data = send(tx, []byte{7, 0, 0, 1, 2, 0})
	if !bytes.Contains(data, tdsUTF16("completion failed")) {
		t.Fatal("completion error missing")
	}
	if len(actions) != 2 {
		t.Fatal("successor invoked after error")
	}
}
func TestFailedPreparedPublicationRemovesHandle(t *testing.T) {
	s := &Server{Handler: Handler{Describe: func(context.Context, Session, Request) ([]Column, error) { return nil, nil }, Execute: func(context.Context, Session, Request, ResultWriter) error { return nil }}}
	c := &connection{ctx: context.Background(), server: s, database: "fixture"}
	err := c.execute(tdsMessage{kind: 3, data: encodeRPC(11, intParam("handle", 0, true), textParam(""), textParam("opaque text"))}, failedConnection{})
	if err == nil || len(c.prepared) != 0 || c.preparedBytes != 0 {
		t.Fatal("failed publish retained prepared handle", err, len(c.prepared), c.preparedBytes)
	}
}

type failedConnection struct{}

func (failedConnection) Read([]byte) (int, error)         { return 0, fmt.Errorf("closed") }
func (failedConnection) Write([]byte) (int, error)        { return 0, fmt.Errorf("closed") }
func (failedConnection) Close() error                     { return nil }
func (failedConnection) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (failedConnection) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (failedConnection) SetDeadline(time.Time) error      { return nil }
func (failedConnection) SetReadDeadline(time.Time) error  { return nil }
func (failedConnection) SetWriteDeadline(time.Time) error { return nil }

func TestCursorInformationIsNotRetainedForFetch(t *testing.T) {
	_, dsn, _ := startClient(t, false, func(s *Server) {
		execute := s.Handler.Execute
		s.Handler.Execute = func(ctx context.Context, session Session, request Request, w ResultWriter) error {
			if request.Cursor {
				if err := w.Message(Diagnostic{Text: "cursor construction notice"}); err != nil {
					return err
				}
			}
			return execute(ctx, session, request, w)
		}
	})
	c := rawClient(t, dsn)
	data := exchange(t, c, 2, intParam("cursor", 0, true), textParam("SELECT many"),
		intParam("scroll", 8, true), intParam("concurrency", 1, true), intParam("count", 0, true))
	handle, ok := returnInt(data, "cursor", 0)
	if !ok || handle <= 0 || data[0] != 0xab || bytes.Count(data, tdsUTF16("cursor construction notice")) != 1 {
		t.Fatalf("cursor construction did not forward one information token: %x", data)
	}
	for i := 0; i < 2; i++ {
		data = exchange(t, c, 7, intParam("", int64(handle), false), intParam("", 2, false), intParam("", 0, false), intParam("", 1, false))
		if bytes.Contains(data, tdsUTF16("cursor construction notice")) || !bytes.Contains(data, rowIntPattern(int64(i), true)) {
			t.Fatal("fetch replayed an invocation message or lost its row")
		}
	}
	exchange(t, c, 9, intParam("", int64(handle), false))
}

func TestCursorInformationWireFailureDoesNotPublishHandle(t *testing.T) {
	var messageError error
	s := &Server{Handler: Handler{
		Describe: func(context.Context, Session, Request) ([]Column, error) { return nil, nil },
		Execute: func(_ context.Context, _ Session, _ Request, w ResultWriter) error {
			messageError = w.Message(Diagnostic{Text: strings.Repeat("n", 3000)})
			if err := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); err != nil {
				return err
			}
			return w.Row([]any{int64(1)})
		},
	}}
	c := &connection{ctx: context.Background(), server: s, database: "fixture"}
	err := c.execute(tdsMessage{kind: 3, data: encodeRPC(2, intParam("cursor", 0, true), textParam("opaque cursor"),
		intParam("scroll", 8, true), intParam("concurrency", 1, true), intParam("count", 0, true))}, failedConnection{})
	if messageError == nil || err == nil || c.nextCursor != 0 || len(c.cursors) != 0 || c.cursorBytes != 0 {
		t.Fatal("failed information delivery admitted a cursor", messageError, err, c.nextCursor, c.cursorBytes)
	}
}

func TestCursorInformationRejectedPayloadDoesNotPublishHandle(t *testing.T) {
	_, dsn, _ := startClient(t, false, func(s *Server) {
		execute := s.Handler.Execute
		s.Handler.Execute = func(ctx context.Context, session Session, request Request, w ResultWriter) error {
			if request.Cursor {
				// A handler ignoring a payload-encoding error must not turn an
				// incomplete response into an admitted cursor snapshot.
				_ = w.Message(Diagnostic{Procedure: strings.Repeat("x", 256)})
			}
			return execute(ctx, session, request, w)
		}
	})
	c := rawClient(t, dsn)
	data := exchange(t, c, 2, intParam("cursor", 0, true), textParam("SELECT many"),
		intParam("scroll", 8, true), intParam("concurrency", 1, true), intParam("count", 0, true))
	if handle, ok := returnInt(data, "cursor", 0); ok && handle > 0 {
		t.Fatalf("ignored invalid diagnostic admitted cursor %d", handle)
	}
	if len(data) == 0 || data[0] != 0xaa || !bytes.Contains(data, tdsUTF16("diagnostic fields exceed wire length limits")) {
		t.Fatalf("missing diagnostic encoding rejection: %x", data)
	}
}

func TestStructuredErrorCompletionAndHandleLifetime(t *testing.T) {
	failure := &DiagnosticError{Diagnostic: Diagnostic{Number: 8115, State: 4, Class: 16, Text: "application failure", Server: "node", Procedure: "load", Line: 70001}}
	var executions atomic.Int64
	_, dsn, _ := startClient(t, false, func(s *Server) {
		execute, describe := s.Handler.Execute, s.Handler.Describe
		s.Handler.Execute = func(ctx context.Context, session Session, r Request, w ResultWriter) error {
			if r.Text == "opaque execute failure" {
				executions.Add(1)
				return fmt.Errorf("wrapped: %w", failure)
			}
			return execute(ctx, session, r, w)
		}
		s.Handler.Describe = func(ctx context.Context, session Session, r Request) ([]Column, error) {
			if r.Text == "opaque describe failure" {
				return nil, failure
			}
			return describe(ctx, session, r)
		}
	})
	c := rawClient(t, dsn)
	check := func(data []byte, rpc bool) {
		t.Helper()
		token, err := tdsDiagnostic(0xaa, failure.Diagnostic)
		if err != nil || !bytes.HasPrefix(data, token) {
			t.Fatalf("missing diagnostic: %x / %v", data, err)
		}
		var tail bytes.Buffer
		if rpc {
			tail.WriteByte(0x79)
			tdsU32(&tail, 1)
			tdsDone(&tail, 0xfe, 2, 0)
		} else {
			tdsDone(&tail, 0xfd, 2, 0)
		}
		if !bytes.Equal(data[len(token):], tail.Bytes()) {
			t.Fatalf("error completion or unpublished handle changed: %x", data)
		}
	}
	if err := writeTDSMessage(c, 1, append(allHeaders(0), tdsUTF16("opaque execute failure")...)); err != nil {
		t.Fatal(err)
	}
	m, err := readTDSMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	check(m.data, false)
	check(exchange(t, c, 11, intParam("handle", 0, true), textParam(""), textParam("opaque describe failure")), true)
	data := exchange(t, c, 11, intParam("handle", 0, true), textParam(""), textParam("SELECT 1"))
	if handle, ok := returnInt(data, "handle", 0); !ok || handle != 1 || executions.Load() != 1 {
		t.Fatal("failed describe consumed handle or executed", handle, ok, executions.Load())
	}
	check(exchange(t, c, 13, intParam("handle", 0, true), textParam(""), textParam("opaque execute failure")), true)
	data = exchange(t, c, 12, intParam("", 2, false))
	if !bytes.Contains(data, tdsUTF16("unknown prepared handle")) {
		t.Fatalf("failed combined request retained handle: %x", data)
	}
	data = exchange(t, c, 12, intParam("", 1, false))
	if !bytes.Contains(data, rowIntPattern(1, false)) || executions.Load() != 2 {
		t.Fatal("failed request corrupted existing prepared handle", executions.Load())
	}
}

func TestStructuredErrorRespectsAttention(t *testing.T) {
	entered := make(chan struct{})
	_, dsn, _ := startClient(t, false, func(s *Server) {
		execute := s.Handler.Execute
		s.Handler.Execute = func(ctx context.Context, session Session, r Request, w ResultWriter) error {
			if r.Text == "opaque cancelled failure" {
				close(entered)
				<-ctx.Done()
				return &DiagnosticError{Diagnostic: Diagnostic{Number: 8115, Class: 16, Text: "cancelled error must not publish"}}
			}
			return execute(ctx, session, r, w)
		}
	})
	c := rawClient(t, dsn)
	if err := writeTDSMessage(c, 1, append(allHeaders(0), tdsUTF16("opaque cancelled failure")...)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler not entered")
	}
	if err := writeTDSMessage(c, 6, nil); err != nil {
		t.Fatal(err)
	}
	m, err := readTDSMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	tdsDone(&want, 0xfd, 0x20, 0)
	if !bytes.Equal(m.data, want.Bytes()) {
		t.Fatalf("cancelled error replaced attention completion: %x", m.data)
	}
	data := exchange(t, c, 11, intParam("handle", 0, true), textParam(""), textParam("SELECT 1"))
	if handle, ok := returnInt(data, "handle", 0); !ok || handle != 1 {
		t.Fatal("attention corrupted next request", handle, ok)
	}
}

func TestStructuredErrorFailedPublicationDropsHandle(t *testing.T) {
	s := &Server{Handler: Handler{
		Describe: func(context.Context, Session, Request) ([]Column, error) { return nil, nil },
		Execute: func(context.Context, Session, Request, ResultWriter) error {
			return &DiagnosticError{Diagnostic: Diagnostic{Number: 8115, Class: 16, Text: "application failure"}}
		},
	}}
	c := &connection{ctx: context.Background(), server: s, database: "fixture"}
	err := c.execute(tdsMessage{kind: 3, data: encodeRPC(13, intParam("handle", 0, true), textParam(""), textParam("opaque text"))}, failedConnection{})
	if err == nil || len(c.prepared) != 0 || c.preparedBytes != 0 {
		t.Fatal("failed error publication retained prepared handle", err, len(c.prepared), c.preparedBytes)
	}
}

func TestGUIDRPCPreparedFreshBindingsAndMalformedRecovery(t *testing.T) {
	var executions, descriptions atomic.Int64
	_, dsn, _ := startClient(t, false, func(server *Server) {
		server.Handler.Describe = func(_ context.Context, _ Session, request Request) ([]Column, error) {
			descriptions.Add(1)
			if request.Text != "GUID echo" || request.Declarations != "@g uniqueidentifier" {
				return nil, fmt.Errorf("unexpected prepare contract")
			}
			return []Column{fixtureColumn("g", 0x24, 16)}, nil
		}
		server.Handler.Execute = func(_ context.Context, _ Session, request Request, writer ResultWriter) error {
			executions.Add(1)
			if request.Text != "GUID echo" || request.Declarations != "@g uniqueidentifier" || len(request.Parameters) != 1 {
				return fmt.Errorf("unexpected execute contract")
			}
			parameter := request.Parameters[0]
			if parameter.Name != "@g" || parameter.Flags != 0 || parameter.Type != (WireType{Kind: 0x24, Size: 16}) {
				return fmt.Errorf("GUID parameter descriptor lost: %+v", parameter)
			}
			if err := writer.Fields([]Column{fixtureColumn("g", 0x24, 16)}); err != nil {
				return err
			}
			return writer.Row([]any{parameter.Value})
		}
	})
	client := rawClient(t, dsn)
	// Send literal GUIDTYPE metadata and bytes: the released driver's byte Valuer
	// uses a binary descriptor and therefore cannot prove this input contract.
	send := func(prefix, guid []byte) []byte {
		t.Helper()
		var request bytes.Buffer
		request.Write(prefix)
		tdsBText(&request, "@g")
		request.WriteByte(0)
		request.Write(guid)
		if err := writeTDSMessage(client, 3, request.Bytes()); err != nil {
			t.Fatal(err)
		}
		response, err := readTDSMessage(client)
		if err != nil {
			t.Fatal(err)
		}
		return response.data
	}
	assertRow := func(data, value []byte) {
		t.Helper()
		pattern := append([]byte{0xd1, byte(len(value))}, value...)
		if len(data) < 13 || data[0] != 0x81 || !bytes.Contains(data, pattern) || data[len(data)-13] != 0xfe || binary.LittleEndian.Uint16(data[len(data)-12:]) != 0 {
			t.Fatalf("GUID result or success completion missing: %x", data)
		}
	}
	direct := encodeRPC(10, textParam("GUID echo"), textParam("@g uniqueidentifier"))
	assertRow(send(direct, append([]byte{0x24, 16, 16}, guidWireBytes()...)), guidWireBytes())
	data := exchange(t, client, 11, intParam("handle", 0, true), textParam("@g uniqueidentifier"), textParam("GUID echo"), intParam("", 1, false))
	handle, ok := returnInt(data, "handle", 0)
	if !ok || handle <= 0 || descriptions.Load() != 1 || executions.Load() != 1 || data[0] != 0x81 {
		t.Fatalf("pure GUID describe/prepare: %x, %d, %d", data, executions.Load(), descriptions.Load())
	}
	prepared := encodeRPC(12, intParam("", int64(handle), false))
	for _, value := range [][]byte{guidWireBytes(), nil, bytes.Repeat([]byte{0xfe}, 16)} {
		assertRow(send(prepared, append([]byte{0x24, 16, byte(len(value))}, value...)), value)
	}
	before := executions.Load()
	for _, malformed := range [][]byte{{0x24}, {0x24, 16}, {0x24, 15, 0}, {0x24, 17, 0}, {0x24, 16, 1, 0}, {0x24, 16, 17}, {0x24, 16, 16, 1, 2}} {
		data := send(prepared, malformed)
		if len(data) < 18 || data[0] != 0xaa || data[len(data)-18] != 0x79 || binary.LittleEndian.Uint32(data[len(data)-17:]) != 1 || data[len(data)-13] != 0xfe || binary.LittleEndian.Uint16(data[len(data)-12:]) != 2 || executions.Load() != before {
			t.Fatalf("malformed GUID reached backend or broke error framing: %x", data)
		}
	}
	// A failed binding must leave the prepared handle and connection reusable.
	assertRow(send(prepared, append([]byte{0x24, 16, 16}, guidWireBytes()...)), guidWireBytes())
	exchange(t, client, 15, intParam("", int64(handle), false))
	if executions.Load() != before+1 || descriptions.Load() != 1 {
		t.Fatal("prepared binding retained values or repeated describe")
	}
}
