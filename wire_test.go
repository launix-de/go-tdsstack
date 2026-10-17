/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func expectTDSPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected rejection")
		}
	}()
	fn()
}
func allHeaders(transaction uint64) []byte {
	var b bytes.Buffer
	tdsU32(&b, 22)
	tdsU32(&b, 18)
	tdsU16(&b, 2)
	tdsU64(&b, transaction)
	tdsU32(&b, 1)
	return b.Bytes()
}
func encodeRPC(id uint16, params ...Parameter) []byte {
	var b bytes.Buffer
	b.Write(allHeaders(0))
	tdsU16(&b, 65535)
	tdsU16(&b, id)
	tdsU16(&b, 0)
	for _, p := range params {
		tdsBText(&b, p.Name)
		b.WriteByte(p.Flags)
		b.WriteByte(p.Type.Kind)
		switch p.Type.Kind {
		case 0x26, 0x68, 0x6d:
			b.WriteByte(byte(p.Type.Size))
		case 0xe7, 0xef, 0xa7, 0xaf, 0xa5, 0xad:
			tdsU16(&b, uint16(p.Type.Size))
			if p.Type.Kind != 0xa5 && p.Type.Kind != 0xad {
				b.Write(p.Type.Collation[:])
			}
		case 0x6a, 0x6c:
			b.Write([]byte{byte(p.Type.Size), p.Type.Precision, p.Type.Scale})
		case 0x28:
		case 0x29, 0x2a, 0x2b:
			b.WriteByte(p.Type.Scale)
		}
		b.Write(encodeWireValue(Column{WireType: p.Type}, p.Value))
	}
	return b.Bytes()
}
func TestPacketFraming(t *testing.T) {
	original := bytes.Repeat([]byte("native-wire"), 1500)
	var b bytes.Buffer
	if err := writeTDSMessage(&b, 3, original); err != nil {
		t.Fatal(err)
	}
	m, err := readTDSMessage(&b)
	if err != nil || m.kind != 3 || !bytes.Equal(m.data, original) {
		t.Fatal(err, m.kind)
	}
	for _, data := range [][]byte{{3, 0, 0, 7, 0, 0, 1, 0}, {3, 0, 0, 8, 0, 0, 1, 0}, {3, 1, 0, 9, 0, 0, 1, 0}} {
		if _, e := readTDSMessage(bytes.NewReader(data)); e == nil {
			t.Fatal("malformed packet accepted", data)
		}
	}
}
func TestTypedRPCNullAndExactValues(t *testing.T) {
	values := []Parameter{
		{Name: "@i", Type: WireType{Kind: 0x26, Size: 8}, Value: int64(9007199254740993)},
		{Name: "@null", Type: WireType{Kind: 0x6a, Size: 17, Precision: 38, Scale: 18}},
		{Name: "@decimal", Type: WireType{Kind: 0x6a, Size: 17, Precision: 38, Scale: 18}, Value: Decimal{"12345678901234567890123456789012345678"}},
		{Name: "@bytes", Type: WireType{Kind: 0xa5, Size: 65535}, Value: []byte{0, 128, 255}},
		{Name: "@unicode", Type: WireType{Kind: 0xe7, Size: 65535}, Value: "x🙂é"},
		{Name: "@time", Type: WireType{Kind: 0x2b, Scale: 7}, Value: Temporal{738944, 123456789012, -60}},
	}
	r, err := decodeTDSRPC(encodeRPC(10, values...))
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range r.arguments {
		if !reflect.DeepEqual(a.value, values[i].Value) || r.wireDescriptors[i].Kind != values[i].Type.Kind || r.wireDescriptors[i].Scale != values[i].Type.Scale {
			t.Fatal(i, a.value, r.wireDescriptors[i])
		}
	}
}
func TestResultStrictMetadataAndFraming(t *testing.T) {
	var b bytes.Buffer
	r := &resultWriter{w: &b, ctx: context.Background()}
	if r.Row([]any{int64(42)}) == nil {
		t.Fatal("row before metadata accepted")
	}
	columns := []Column{{Name: "x", WireType: WireType{Kind: 0x26, Size: 8}, Flags: 1}}
	if e := r.Fields(columns); e != nil {
		t.Fatal(e)
	}
	if r.Fields(columns) == nil {
		t.Fatal("duplicate fields accepted")
	}
	before := b.Len()
	if r.Row([]any{"wrong"}) == nil {
		t.Fatal("bad wire scalar accepted")
	}
	if b.Len() != before {
		t.Fatal("half ROW token published")
	}
	var empty bytes.Buffer
	r = &resultWriter{w: &empty}
	if e := r.Fields(columns); e != nil {
		t.Fatal(e)
	}
	if e := r.Row([]any{nil}); e != nil {
		t.Fatal(e)
	}
	if e := r.Done(Completion{Rows: 1}); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(empty.Bytes(), []byte{0xd1, 0}) {
		t.Fatal("typed NULL lost")
	}
	if e := r.Fields(columns); e != nil {
		t.Fatal("second result metadata", e)
	}
}
func TestConsecutiveCompletionsWithoutMetadata(t *testing.T) {
	var b bytes.Buffer
	var completions []Completion
	r := &resultWriter{w: &b, completion: func(c Completion) error {
		completions = append(completions, c)
		return nil
	}}
	for _, c := range []Completion{{Rows: 2, More: true}, {Rows: 3, More: true}, {NoCount: true}} {
		if err := r.Done(c); err != nil {
			t.Fatal(err)
		}
		if r.Row([]any{int64(1)}) == nil {
			t.Fatal("completion must not admit rows without metadata")
		}
	}
	if len(completions) != 3 || b.Len() != 39 {
		t.Fatalf("completion callbacks or tokens missing: %d / %d", len(completions), b.Len())
	}
	for i, expected := range []struct {
		status uint16
		rows   uint64
	}{{0x11, 2}, {0x11, 3}, {0, 0}} {
		token := b.Bytes()[i*13 : (i+1)*13]
		if token[0] != 0xfd || binary.LittleEndian.Uint16(token[1:3]) != expected.status || binary.LittleEndian.Uint64(token[5:13]) != expected.rows {
			t.Fatalf("unexpected completion %d: %x", i, token)
		}
	}
	if r.Done(Completion{}) == nil || len(completions) != 3 || b.Len() != 39 {
		t.Fatal("a final completion must reject further completions before callbacks or writes")
	}
}

func TestMalformedHeadersUTF16PLPAndCollation(t *testing.T) {
	for _, x := range [][]byte{nil, {4, 0, 0}, {4, 0, 0, 0}, append(allHeaders(0), 0)} {
		if len(x) > 22 {
			x[4] = 1
		}
		if _, e := tdsStripHeaders(x); e == nil {
			t.Fatal("bad headers", x)
		}
	}
	for _, x := range [][]byte{{0}, {0, 0xd8}, {0, 0xdc}, {0, 0xd8, 1, 0}} {
		if _, e := tdsText(x); e == nil {
			t.Fatal("bad UTF16", x)
		}
	}
	for _, x := range [][]byte{{0xe7, 255, 255, 9, 4, 0xd0, 0, 52, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 'a', 0, 0, 0, 0, 0}, {0x26, 3, 0}, {0xff}} {
		d := tdsDecoder{data: x}
		d.parameter()
		if d.err == nil {
			t.Fatal("bad parameter", x)
		}
	}
	cp := []byte{9, 4, 0xd0, 0, 52}
	v, e := tdsDecodeCharacter([]byte{0x80, 0xe4}, cp)
	if e != nil || v != "€ä" {
		t.Fatal(v, e)
	}
	if _, e = tdsDecodeCharacter([]byte{0x81}, cp); e == nil {
		t.Fatal("undefined codepage byte")
	}
}
func TestTransactionDecodeIsActionNotSQL(t *testing.T) {
	var b bytes.Buffer
	b.Write(allHeaders(17))
	tdsU16(&b, 7)
	b.Write([]byte{0, 1, 2, 0})
	r, e := decodeTransaction(b.Bytes())
	if e != nil || r.Action != Commit || !r.Successor || r.SuccessorIsolation != 2 {
		t.Fatal(r, e)
	}
	data := b.Bytes()
	data[len(data)-1] = 1
	if _, e = decodeTransaction(data); e == nil {
		t.Fatal("invalid successor name")
	}
}
func TestResponseShortWrite(t *testing.T) {
	if err := tdsWriteAll(zeroWriter{}, []byte{1}); err != io.ErrShortWrite {
		t.Fatal(err)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
func TestLoginBounds(t *testing.T) {
	data := make([]byte, 94)
	binary.LittleEndian.PutUint32(data, 94)
	binary.LittleEndian.PutUint32(data[4:], 0x74000004)
	binary.LittleEndian.PutUint16(data[40:], 93)
	binary.LittleEndian.PutUint16(data[42:], 1)
	if _, e := decodeTDSLogin(data); e == nil {
		t.Fatal("out-of-bounds login accepted")
	}
}

func TestInformationMessageWireContract(t *testing.T) {
	var b bytes.Buffer
	w := &resultWriter{w: &b, ctx: context.Background()}
	message := Diagnostic{Number: 70001, State: 5, Class: 9, Text: "ready", Server: "node", Procedure: "load", Line: 70000}
	if err := w.Message(message); err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("ab2800711101000509050072006500610064007900046e006f0064006500046c006f006100640070110100")
	if !bytes.Equal(b.Bytes(), want) || w.fields || w.done || w.count != 0 {
		t.Fatalf("unexpected information token or result state: %x", b.Bytes())
	}
	if err := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Row([]any{int64(1)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Message(message); err != nil || w.count != 1 {
		t.Fatal("information changed the active result", err, w.count)
	}
	if err := w.Done(Completion{Rows: 1, More: true}); err != nil {
		t.Fatal(err)
	}
	if err := w.Message(message); err != nil {
		t.Fatal("information between results", err)
	}
	if err := w.Done(Completion{NoCount: true}); err != nil {
		t.Fatal(err)
	}
	before := b.Len()
	if w.Message(message) == nil || b.Len() != before {
		t.Fatal("information after final completion changed the response")
	}
}

func TestInformationMessageEncodingBounds(t *testing.T) {
	name := strings.Repeat("🙂", 127) + "x"
	for _, message := range []Diagnostic{
		{Text: strings.Repeat("x", 32760)},
		{Text: strings.Repeat("🙂", 16380)},
		{Text: strings.Repeat("x", 32250), Server: name, Procedure: name},
		{Text: "Grüße 🙂", Server: name, Procedure: name},
	} {
		var b bytes.Buffer
		w := &resultWriter{w: &b}
		if err := w.Message(message); err != nil {
			t.Fatal(err)
		}
		data := b.Bytes()
		if data[0] != 0xab || int(binary.LittleEndian.Uint16(data[1:3])) != len(data)-3 ||
			int(binary.LittleEndian.Uint16(data[9:11])) != len(tdsUTF16(message.Text))/2 {
			t.Fatalf("information lengths do not describe their actual payload: %d", len(data))
		}
		at := 11 + len(tdsUTF16(message.Text))
		for _, name := range []string{message.Server, message.Procedure} {
			length := int(data[at]) * 2
			decoded, err := tdsText(data[at+1 : at+1+length])
			if err != nil || decoded != name {
				t.Fatalf("information name changed at a UTF-16 boundary: %q / %q / %v", decoded, name, err)
			}
			at += 1 + length
		}
	}
	for _, message := range []Diagnostic{
		{Text: strings.Repeat("x", 32761)},
		{Text: strings.Repeat("🙂", 16381)},
		{Text: strings.Repeat("x", 32760), Server: "x"},
		{Text: strings.Repeat("x", 32251), Server: name, Procedure: name},
		{Server: strings.Repeat("🙂", 128)},
		{Server: strings.Repeat("x", 256)},
		{Procedure: strings.Repeat("x", 256)},
		{Procedure: strings.Repeat("🙂", 128)},
		{Text: string([]byte{0xff})},
		{Server: string([]byte{0xff})},
		{Procedure: string([]byte{0xff})},
	} {
		var b bytes.Buffer
		w := &resultWriter{w: &b}
		if w.Message(message) == nil || b.Len() != 0 {
			t.Fatalf("invalid information published partial framing: %#v", message)
		}
		if err := w.Message(Diagnostic{Text: "valid successor"}); err != nil {
			t.Fatal("rejected payload poisoned an untouched response", err)
		}
	}
}

type shortMessageWriter struct{ bytes.Buffer }

func (w *shortMessageWriter) Write(data []byte) (int, error) {
	if len(data) > 2 {
		data = data[:2]
	}
	return w.Buffer.Write(data)
}
func TestInformationMessageCancellationAndShortWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var b bytes.Buffer
	w := &resultWriter{w: &b, ctx: ctx}
	cancel()
	if err := w.Message(Diagnostic{Text: "cancelled"}); !errors.Is(err, context.Canceled) || b.Len() != 0 {
		t.Fatal("cancelled request emitted information", err)
	}
	short := &shortMessageWriter{}
	w = &resultWriter{w: short}
	if err := w.Message(Diagnostic{Text: "short writes"}); err != nil || short.Len() != 41 {
		t.Fatal("short writes lost information framing", err, short.Len())
	}
	w = &resultWriter{w: zeroWriter{}}
	if !errors.Is(w.Message(Diagnostic{Text: "unwritable"}), io.ErrShortWrite) ||
		!errors.Is(w.Message(Diagnostic{Text: "successor"}), io.ErrShortWrite) ||
		!errors.Is(w.Done(Completion{}), io.ErrShortWrite) {
		t.Fatal("information wire failure was not retained")
	}
}

func TestInformationMessagesParallelCallbacks(t *testing.T) {
	var b bytes.Buffer
	w := &resultWriter{w: &b}
	var producers sync.WaitGroup
	for i := 0; i < 32; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			if err := w.Message(Diagnostic{Text: "complete message 🙂"}); err != nil {
				t.Error(err)
			}
		}()
	}
	producers.Wait()
	data := b.Bytes()
	for i := 0; i < 32; i++ {
		if len(data) < 3 || data[0] != 0xab {
			t.Fatal("concurrent messages interleaved their token framing")
		}
		length := 3 + int(binary.LittleEndian.Uint16(data[1:3]))
		if length > len(data) {
			t.Fatal("incomplete concurrent information token")
		}
		data = data[length:]
	}
	if len(data) != 0 || w.count != 0 || w.fields || w.done {
		t.Fatal("information callbacks changed result state or row count")
	}
}
