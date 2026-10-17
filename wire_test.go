/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"reflect"
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

// These literal fixtures keep GUID byte order independent of the value encoder.
func guidWireBytes() []byte {
	return []byte{0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
}

func TestGUIDResultWireBytesAndValidation(t *testing.T) {
	column := Column{Name: "g", Flags: 1, WireType: WireType{Kind: 0x24, Size: 16}}
	var output bytes.Buffer
	writer := &resultWriter{w: &output}
	if err := writer.Fields([]Column{column}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Row([]any{guidWireBytes()}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Row([]any{nil}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Done(Completion{Rows: 2}); err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("8101000000000001002410016700d11067452301ab89efcd0123456789abcdefd100fd100000000200000000000000")
	if err != nil || !bytes.Equal(output.Bytes(), want) {
		t.Fatalf("GUID metadata, payload, NULL or completion changed: %x, %v", output.Bytes(), err)
	}
	for _, size := range []int{0, 1, 15, 17, 255, 65535} {
		var bad bytes.Buffer
		writer := &resultWriter{w: &bad}
		invalid := column
		invalid.Size = size
		if err := writer.Fields([]Column{invalid}); err == nil || bad.Len() != 0 {
			t.Fatalf("invalid GUID descriptor %d published bytes", size)
		}
	}
	for _, value := range []any{[]byte(nil), []byte{}, make([]byte, 15), make([]byte, 17), "01234567-89ab-cdef-0123-456789abcdef", [16]byte{}} {
		var bad bytes.Buffer
		writer := &resultWriter{w: &bad}
		if err := writer.Fields([]Column{column}); err != nil {
			t.Fatal(err)
		}
		before := bad.Len()
		if err := writer.Row([]any{value}); err == nil || bad.Len() != before {
			t.Fatalf("invalid GUID payload %T published a partial row", value)
		}
	}
}

func TestGUIDRPCDecodeLengthsAndOwnership(t *testing.T) {
	for _, value := range [][]byte{nil, make([]byte, 16), guidWireBytes()} {
		encoded := append([]byte{0x24, 16, byte(len(value))}, value...)
		decoder := tdsDecoder{data: encoded}
		got := decoder.parameter()
		if decoder.err != nil || decoder.descriptor != (WireType{Kind: 0x24, Size: 16}) || len(decoder.data) != 0 {
			t.Fatalf("GUID decoder: %v, %+v, %x", decoder.err, decoder.descriptor, decoder.data)
		}
		if value == nil {
			if got != nil {
				t.Fatal("NULL GUID is not nil")
			}
		} else {
			if !bytes.Equal(got.([]byte), value) {
				t.Fatalf("GUID bytes changed: %x", got)
			}
			encoded[3] = 0
			if !bytes.Equal(got.([]byte), value) {
				t.Fatal("decoded GUID borrows the packet buffer")
			}
		}
	}
	for size := 0; size < 256; size++ {
		if size == 16 {
			continue
		}
		decoder := tdsDecoder{data: []byte{0x24, byte(size), 0}}
		decoder.parameter()
		if decoder.err == nil {
			t.Fatalf("invalid GUID descriptor length %d accepted", size)
		}
	}
	for size := 1; size < 256; size++ {
		if size == 16 {
			continue
		}
		decoder := tdsDecoder{data: append([]byte{0x24, 16, byte(size)}, make([]byte, size)...)}
		decoder.parameter()
		if decoder.err == nil {
			t.Fatalf("invalid GUID value length %d accepted", size)
		}
	}
	complete := append([]byte{0x24, 16, 16}, guidWireBytes()...)
	for size := 1; size < len(complete); size++ {
		decoder := tdsDecoder{data: complete[:size]}
		decoder.parameter()
		if decoder.err == nil {
			t.Fatalf("truncated GUID of %d bytes accepted", size)
		}
	}
}
