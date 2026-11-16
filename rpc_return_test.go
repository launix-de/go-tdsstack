/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	tdsdriver "github.com/denisenkom/go-mssqldb"
)

func TestRPCReturnValueGolden(t *testing.T) {
	got, err := encodeReturnValues([]ReturnValue{{WireType: WireType{Kind: 0x26, Size: 4},
		Name: "@out", Ordinal: 2, Status: 1, Value: int64(42)}})
	// RETURNVALUE, original ordinal 2, UTF-16 name, status/user type/flags,
	// INTN descriptor and length-prefixed value. Flags 0 must not select INT4.
	want, _ := hex.DecodeString("ac02000440006f0075007400010000000000002604042a000000")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("RETURNVALUE: %x, %v; want %x", got, err, want)
	}
}

func TestRPCInputCharacterDescriptorsRemainExplicit(t *testing.T) {
	for _, kind := range []byte{0xa7, 0xe7} {
		for _, value := range []any{nil, "Grüße"} {
			want := WireType{Kind: kind, Size: 40, Collation: [5]byte{9, 4, 0xd0, 0, 52}}
			decoded, err := decodeTDSRPC(encodeRPC(10, Parameter{Name: "@v", Type: want, Value: value}))
			if err != nil {
				t.Fatal(err)
			}
			parameters := rpcParameters(decoded, 0)
			if len(parameters) != 1 || parameters[0].Type != want || parameters[0].Value != value {
				t.Fatalf("character wire descriptor lost: %#v, want %#v", parameters, want)
			}
		}
	}
}

func TestRPCSignedStatusStreamGolden(t *testing.T) {
	_, dsn, _ := startClient(t, false, func(s *Server) {
		s.Handler.Execute = func(_ context.Context, _ Session, _ Request, w ResultWriter) error {
			status := int32(-17)
			return w.Done(Completion{ReturnStatus: &status})
		}
	})
	data := exchange(t, rawClient(t, dsn), 10, textParam("opaque"))
	// DONEINPROC (MORE | COUNT), signed RETURNSTATUS, final DONEPROC.
	var expected bytes.Buffer
	expected.Write([]byte{0xff, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	expected.Write([]byte{0x79, 0xef, 0xff, 0xff, 0xff})
	expected.Write([]byte{0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if !bytes.Equal(data, expected.Bytes()) {
		t.Fatalf("RPC status framing: %x; want %x", data, expected.Bytes())
	}
}

func readReturnValues(t *testing.T, data []byte) []ReturnValue {
	t.Helper()
	d := tdsDecoder{data: data}
	var values []ReturnValue
	for len(d.data) != 0 && d.err == nil {
		if kind := d.u8(); kind != 0xac {
			t.Fatalf("unexpected return token %x", kind)
		}
		value := ReturnValue{Ordinal: d.u16()}
		value.Name = d.text(int(d.u8()))
		value.Status, value.UserType, value.Flags = d.u8(), d.u32(), d.u16()
		value.Value = d.parameter()
		value.WireType = d.descriptor
		values = append(values, value)
	}
	if d.err != nil {
		t.Fatal(d.err)
	}
	return values
}

func TestRPCReturnValueTypesAndLOBOrder(t *testing.T) {
	values := []ReturnValue{
		{WireType: WireType{Kind: 0xe7, Size: 65535, Collation: [5]byte{9, 4, 0xd0, 0, 52}}, Name: "@unicode", Ordinal: 0, Status: 1, Value: "Grüße🙂"},
		{WireType: WireType{Kind: 0x26, Size: 8}, Name: "@integer", Ordinal: 1, Status: 1, Value: int64(9007199254740993)},
		{WireType: WireType{Kind: 0xa5, Size: 65535}, Name: "@binary", Ordinal: 2, Status: 1, Value: []byte{0, 255, 3}},
		{WireType: WireType{Kind: 0x6a, Size: 17, Precision: 38, Scale: 18}, Name: "@decimal", Ordinal: 3, Status: 1, Value: Decimal{"12345678901234567890123456789012345678"}},
		{WireType: WireType{Kind: 0x2b, Size: 10, Scale: 7}, Name: "@time", Ordinal: 4, Status: 1, Value: Temporal{738944, 123456789012, -60}},
		{WireType: WireType{Kind: 0x26, Size: 4}, Name: "@null", Ordinal: 5, Status: 1},
		{WireType: WireType{Kind: 0x68, Size: 1}, Ordinal: 6, Status: 2, Value: true},
	}
	encoded, err := encodeReturnValues(values)
	if err != nil {
		t.Fatal(err)
	}
	want := []ReturnValue{values[1], values[3], values[4], values[5], values[6], values[0], values[2]}
	if got := readReturnValues(t, encoded); !reflect.DeepEqual(got, want) {
		t.Fatalf("typed output or original ordinal changed: %#v; want %#v", got, want)
	}
}

func TestRPCReturnCompletionValidationAndOwnership(t *testing.T) {
	status := int32(-17)
	value := ReturnValue{WireType: WireType{Kind: 0xa5, Size: 8}, Name: "@b", Ordinal: 2, Status: 1, Value: []byte{1, 2, 3}}
	values := []ReturnValue{value}
	var body bytes.Buffer
	w := &resultWriter{w: &body, rpc: true, ctx: context.Background()}
	if err := w.Done(Completion{ReturnStatus: &status, ReturnValues: values}); err != nil {
		t.Fatal(err)
	}
	status, values[0].Name, value.Value.([]byte)[0] = 9, "changed", 99
	var tail bytes.Buffer
	w.rpcCompletion(&tail, "", 0)
	if !bytes.Equal(tail.Bytes()[:5], []byte{0x79, 0xef, 0xff, 0xff, 0xff}) {
		t.Fatalf("borrowed status or wrong signed encoding: %x", tail.Bytes())
	}
	got := readReturnValues(t, tail.Bytes()[5:])
	if len(got) != 1 || got[0].Name != "@b" || !bytes.Equal(got[0].Value.([]byte), []byte{1, 2, 3}) {
		t.Fatalf("completion borrowed mutable output: %#v", got)
	}
	for _, fixture := range []struct {
		name string
		rpc  bool
		c    Completion
	}{
		{"batch status", false, Completion{ReturnStatus: &status}},
		{"intermediate status", true, Completion{More: true, ReturnStatus: &status}},
		{"wrong descriptor", true, Completion{ReturnValues: []ReturnValue{{Status: 1}}}},
		{"wrong payload", true, Completion{ReturnValues: []ReturnValue{{WireType: WireType{Kind: 0x26, Size: 4}, Status: 1, Value: "bad"}}}},
		{"wrong status", true, Completion{ReturnValues: []ReturnValue{{WireType: value.WireType, Status: 3}}}},
		{"long name", true, Completion{ReturnValues: []ReturnValue{{WireType: value.WireType, Status: 1, Name: strings.Repeat("🙂", 128)}}}},
		{"encrypted", true, Completion{ReturnValues: []ReturnValue{{WireType: value.WireType, Status: 1, Flags: 0x800}}}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var b bytes.Buffer
			r := &resultWriter{w: &b, rpc: fixture.rpc, ctx: context.Background()}
			if err := r.Done(fixture.c); err == nil || b.Len() != 0 {
				t.Fatalf("invalid completion published bytes: %x, %v", b.Bytes(), err)
			}
		})
	}
}

func TestReleasedClientRPCStatusAndOutputs(t *testing.T) {
	db, _, _ := startClient(t, false, func(s *Server) {
		s.Handler.Metadata = func(_ context.Context, _ Session, r Request, w ResultWriter) error {
			if !r.RPC || r.Procedure != "fixture_proc" || len(r.Parameters) != 3 {
				return fmt.Errorf("unexpected RPC invocation: %#v", r)
			}
			status := int32(r.Parameters[0].Value.(int64))
			var outputs []ReturnValue
			for i, p := range r.Parameters {
				if int(p.Ordinal) != i {
					return fmt.Errorf("wrong original ordinal: %d", p.Ordinal)
				}
				if i == 0 {
					continue
				}
				if p.Flags != 1 {
					return fmt.Errorf("missing output flag")
				}
				value := any(int64(42))
				if p.Name == "@text" {
					value = "Grüße🙂"
				}
				outputs = append(outputs, ReturnValue{WireType: p.Type, Name: p.Name, Ordinal: p.Ordinal, Status: 1, Value: value})
			}
			if err := w.Done(Completion{Rows: 3, More: true}); err != nil {
				return err
			}
			if err := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); err != nil {
				return err
			}
			if err := w.Row([]any{int64(77)}); err != nil {
				return err
			}
			return w.Done(Completion{CountRows: true, ReturnStatus: &status, ReturnValues: outputs})
		}
	})
	for _, status := range []int32{0, -17, math.MinInt32, math.MaxInt32} {
		var got tdsdriver.ReturnStatus
		var integer int64
		var text string
		rows, err := db.Query("fixture_proc", sql.Named("status", status), sql.Named("text", sql.Out{Dest: &text}), sql.Named("integer", sql.Out{Dest: &integer}), &got)
		if err != nil {
			t.Fatal(err)
		}
		var row int64
		if !rows.Next() || rows.Scan(&row) != nil || row != 77 {
			t.Fatalf("result row changed: %d, %v", row, rows.Err())
		}
		if rows.Next() {
			t.Fatal("unexpected extra row")
		}
		for rows.NextResultSet() {
			for rows.Next() {
				t.Fatal("unexpected extra row")
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		if int32(got) != status || integer != 42 || text != "Grüße🙂" {
			t.Fatalf("status/output: %d, %d, %q; want %d, 42, unicode", got, integer, text, status)
		}
	}
	var implicit tdsdriver.ReturnStatus = 99
	if _, err := db.Exec("sp_executesql", sql.Named("stmt", "SELECT 1"), &implicit); err != nil || implicit != 0 {
		t.Fatalf("next request retained return status: %d, %v", implicit, err)
	}
}

func TestRPCPreparedOutputsRetainOriginalOrdinals(t *testing.T) {
	_, dsn, _ := startClient(t, false, func(s *Server) {
		s.Handler.Execute = func(_ context.Context, _ Session, r Request, w ResultWriter) error {
			if !r.RPC || len(r.Parameters) != 1 || r.Parameters[0].Flags != 1 {
				return fmt.Errorf("missing prepared output")
			}
			p := r.Parameters[0]
			return w.Done(Completion{ReturnValues: []ReturnValue{{WireType: p.Type, Name: p.Name, Ordinal: p.Ordinal, Status: 1, Value: int64(91)}}})
		}
	})
	c := rawClient(t, dsn)
	check := func(data []byte, ordinal uint16) {
		t.Helper()
		if value, ok := returnInt(data, "@v", ordinal); !ok || value != 91 {
			t.Fatalf("prepared output ordinal %d: %x", ordinal, data)
		}
	}
	check(exchange(t, c, 10, textParam("opaque"), textParam("@v int OUTPUT"), intParam("@v", 7, true)), 2)
	data := exchange(t, c, 13, intParam("handle", 0, true), textParam("@v int OUTPUT"), textParam("opaque"), intParam("@v", 8, true))
	check(data, 3)
	handle, ok := returnInt(data, "handle", 0)
	if !ok {
		t.Fatal("missing prepared handle")
	}
	check(exchange(t, c, 12, intParam("", int64(handle), false), intParam("@v", 9, true)), 1)
}

func TestRPCFailedOrCancelledHandlerDiscardsOutputs(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelRequest), func(t *testing.T) {
			entered := make(chan struct{})
			_, dsn, _ := startClient(t, false, func(s *Server) {
				s.Handler.Execute = func(ctx context.Context, _ Session, _ Request, w ResultWriter) error {
					status := int32(37)
					if err := w.Done(Completion{ReturnStatus: &status, ReturnValues: []ReturnValue{{WireType: WireType{Kind: 0x26, Size: 4}, Name: "@out", Status: 1, Value: int64(123)}}}); err != nil {
						return err
					}
					close(entered)
					if cancelRequest {
						<-ctx.Done()
					}
					return fmt.Errorf("failure after staging")
				}
			})
			c := rawClient(t, dsn)
			if err := writeTDSMessage(c, 3, encodeRPC(10, textParam("opaque"))); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("handler not entered")
			}
			if cancelRequest {
				if err := writeTDSMessage(c, 6, nil); err != nil {
					t.Fatal(err)
				}
			}
			message, err := readTDSMessage(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := returnInt(message.data, "@out", 0); ok || bytes.Contains(message.data, []byte{0x79, 37, 0, 0, 0}) {
				t.Fatalf("failed request published staged outputs: %x", message.data)
			}
		})
	}
}
