/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

var _ DiagnosticWriter = (*resultWriter)(nil)
var _ DiagnosticWriter = (*snapshotWriter)(nil)

func TestTypedDiagnosticsSelectKindAndCompletion(t *testing.T) {
	var wire, want bytes.Buffer
	r := &resultWriter{w: &wire, active: func() bool { return true }}
	messages := []struct {
		kind    MessageKind
		token   byte
		payload Message
	}{
		{KindInfo, 0xab, Message{Number: 71, Severity: 25, Text: "informational Grüße"}},
		{KindError, 0xaa, Message{Number: 72, Severity: 0, Text: "explicit error"}},
		{KindError, 0xaa, Message{Number: 73, Severity: 16, Text: "second error"}},
	}
	for _, message := range messages {
		if err := r.Diagnostic(message.kind, message.payload); err != nil {
			t.Fatal(err)
		}
		token, err := tdsDiagnostic(message.token, message.payload)
		if err != nil {
			t.Fatal(err)
		}
		want.Write(token)
	}
	// Fields must not discard an ERROR emitted before metadata.
	if err := r.Fields([]Column{}); err != nil {
		t.Fatal(err)
	}
	want.Write([]byte{0x81, 0, 0})
	if err := r.Done(Completion{Rows: 7, More: true}); err != nil {
		t.Fatal(err)
	}
	tdsDone(&want, 0xfd, 2|4|1|0x10, 7)
	if err := r.Info(Message{Severity: 25, Text: "next result"}); err != nil {
		t.Fatal(err)
	}
	token, _ := tdsDiagnostic(0xab, Message{Severity: 25, Text: "next result"})
	want.Write(token)
	if err := r.Done(Completion{NoCount: true}); err != nil {
		t.Fatal(err)
	}
	tdsDone(&want, 0xfd, 4, 0)
	if !bytes.Equal(wire.Bytes(), want.Bytes()) || r.diagnosticStatus() != 2 {
		t.Fatalf("kind/completion mismatch: %x != %x", wire.Bytes(), want.Bytes())
	}
	before := wire.Len()
	if r.Diagnostic(KindError, Message{}) == nil || wire.Len() != before {
		t.Fatal("late diagnostic changed a completed result")
	}
}

func TestTypedDiagnosticFailuresAreStickyAndDoNotPublishTokens(t *testing.T) {
	for _, invalid := range []struct {
		kind    MessageKind
		payload Message
	}{
		{0, Message{}}, {MessageKind(255), Message{}},
		{KindError, Message{Text: strings.Repeat("x", 32761)}},
	} {
		var wire bytes.Buffer
		r := &resultWriter{w: &wire}
		err := r.Diagnostic(invalid.kind, invalid.payload)
		if err == nil || r.Info(Message{}) != err || r.Done(Completion{}) != err || wire.Len() != 0 || r.diagnosticStatus() != 0 {
			t.Fatal("invalid diagnostic escaped its sticky boundary", err, wire.Len())
		}
	}
	r := &resultWriter{w: zeroWriter{}}
	if err := r.Diagnostic(KindError, Message{}); err == nil || r.Info(Message{}) != err || r.diagnosticStatus() != 0 {
		t.Fatal("failed write marked an ERROR as published", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wire bytes.Buffer
	r = &resultWriter{w: &wire, ctx: ctx}
	if err := r.Diagnostic(KindError, Message{}); !errors.Is(err, context.Canceled) || wire.Len() != 0 {
		t.Fatal("cancelled diagnostic published", err)
	}
}

func TestParallelTypedDiagnosticsKeepWholeTokens(t *testing.T) {
	var wire bytes.Buffer
	r := &resultWriter{w: &wire}
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := r.Diagnostic(KindError, Message{Number: uint32(i + 1), Text: "parallel"}); err != nil {
				failures <- err
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	data := wire.Bytes()
	seen := map[uint32]bool{}
	for len(data) > 0 {
		if len(data) < 7 || data[0] != 0xaa {
			t.Fatal("interleaved token")
		}
		n := 3 + int(binary.LittleEndian.Uint16(data[1:3]))
		if n > len(data) {
			t.Fatal("truncated token")
		}
		seen[binary.LittleEndian.Uint32(data[3:7])] = true
		data = data[n:]
	}
	if len(seen) != 16 {
		t.Fatal("lost parallel diagnostic", seen)
	}
}

func TestStreamingDiagnosticsAndTerminalErrorWire(t *testing.T) {
	first := Message{Number: 91, State: 2, Severity: 16, Text: "first error", Procedure: "opaque", Line: 31}
	last := Message{Number: 92, State: 3, Severity: 11, Text: "terminal error", Line: 32}
	_, dsn, _ := startClient(t, false, func(s *Server) {
		s.Handler.Execute = func(_ context.Context, _ Session, _ Request, w ResultWriter) error {
			if err := w.(DiagnosticWriter).Diagnostic(KindError, first); err != nil {
				return err
			}
			return fmt.Errorf("wrapped: %w", &DiagnosticError{Message: last})
		}
	})
	c := rawClient(t, dsn)
	for _, rpc := range []bool{false, true} {
		var data []byte
		if rpc {
			data = exchange(t, c, 10, textParam("opaque"))
		} else {
			if err := writeTDSMessage(c, 1, append(allHeaders(0), tdsUTF16("opaque")...)); err != nil {
				t.Fatal(err)
			}
			m, err := readTDSMessage(c)
			if err != nil {
				t.Fatal(err)
			}
			data = m.data
		}
		var want bytes.Buffer
		for _, payload := range []Message{first, last} {
			token, _ := tdsDiagnostic(0xaa, payload)
			want.Write(token)
		}
		if rpc {
			want.WriteByte(0x79)
			tdsU32(&want, 1)
			tdsDone(&want, 0xfe, 2, 0)
		} else {
			tdsDone(&want, 0xfd, 2, 0)
		}
		if !bytes.Equal(data, want.Bytes()) {
			t.Fatalf("lost ordered ERROR sequence: %x != %x", data, want.Bytes())
		}
	}
}

func TestStreamingDiagnosticsContinueAndCursorForwarding(t *testing.T) {
	payload := Message{Number: 101, Severity: 0, Text: "explicit recoverable error"}
	_, dsn, _ := startClient(t, false, func(s *Server) {
		s.Handler.Execute = func(_ context.Context, _ Session, _ Request, w ResultWriter) error {
			if err := w.(DiagnosticWriter).Diagnostic(KindError, payload); err != nil {
				return err
			}
			if err := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); err != nil {
				return err
			}
			if err := w.Row([]any{int64(9)}); err != nil {
				return err
			}
			return w.Done(Completion{Rows: 1})
		}
	})
	c := rawClient(t, dsn)
	data := exchange(t, c, 10, textParam("opaque"))
	token, _ := tdsDiagnostic(0xaa, payload)
	var tail bytes.Buffer
	tdsDone(&tail, 0xff, 2|1|0x10, 1)
	tail.WriteByte(0x79)
	tdsU32(&tail, 0)
	tdsDone(&tail, 0xfe, 2, 0)
	if !bytes.HasPrefix(data, token) || !bytes.Contains(data, rowIntPattern(9, false)) || !bytes.HasSuffix(data, tail.Bytes()) {
		t.Fatalf("ERROR changed continuation or RPC DONE: %x", data)
	}
	data = exchange(t, c, 2, intParam("cursor", 0, true), textParam("opaque"), intParam("scroll", 8, true), intParam("concurrency", 1, true), intParam("count", 0, true))
	handle, ok := returnInt(data, "cursor", 0)
	var final bytes.Buffer
	tdsDone(&final, 0xfe, 2, 0)
	var firstDone bytes.Buffer
	tdsDone(&firstDone, 0xff, 3, 0)
	if !ok || handle <= 0 || !bytes.HasPrefix(data, token) || !bytes.Contains(data, firstDone.Bytes()) || !bytes.HasSuffix(data, final.Bytes()) {
		t.Fatalf("cursor lost typed diagnostic/completion: %x", data)
	}
	data = exchange(t, c, 7, intParam("", int64(handle), false), intParam("", 1, false), intParam("", 0, false), intParam("", 1, false))
	if bytes.Contains(data, token) || !bytes.Contains(data, rowIntPattern(9, true)) {
		t.Fatal("cursor retained diagnostic callback or lost native row")
	}
}

func TestSnapshotDiagnosticRejectsLateCalls(t *testing.T) {
	var wire bytes.Buffer
	sink := &resultWriter{w: &wire}
	s := &snapshotWriter{ctx: context.Background(), diagnostic: sink.Diagnostic}
	if err := s.Info(Message{Text: "before fields"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Done(Completion{}); err != nil {
		t.Fatal(err)
	}
	before := wire.Len()
	if s.Diagnostic(KindError, Message{}) == nil || wire.Len() != before {
		t.Fatal("late cursor diagnostic published")
	}
}
