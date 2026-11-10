/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestTDSExactNumericWireValues(t *testing.T) {
	for _, fixture := range []struct {
		kind                   byte
		precision, scale, size int
		text                   string
	}{{0x6a, 9, 2, 5, "-1234567.89"}, {0x6c, 19, 4, 9, "900719925474099.1234"}, {0x6a, 28, 8, 13, "12345678901234567890.12345678"}, {0x6a, 38, 10, 17, "9999999999999999999999999999.9999999999"}, {0x6e, 19, 4, 8, "-922337203685477.5808"}, {0x6e, 19, 4, 8, "922337203685477.5807"}, {0x6e, 10, 4, 4, "-214748.3648"}} {
		column := tdsColumn{WireType: WireType{Kind: fixture.kind, Precision: byte(fixture.precision), Scale: byte(fixture.scale), Size: fixture.size}}
		coefficient := strings.ReplaceAll(fixture.text, ".", "")
		var value any = Decimal{coefficient}
		if fixture.kind == 0x6e {
			n, err := strconv.ParseInt(coefficient, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			value = n
		}
		encoded := tdsEncodeNumeric(column, value)
		metadata := []byte{fixture.kind, byte(fixture.size)}
		if fixture.kind != 0x6e {
			metadata = append(metadata, byte(fixture.precision), byte(fixture.scale))
		}
		decoder := tdsDecoder{data: append(metadata, encoded...)}
		actual := decoder.parameter()
		if decoder.err != nil || !reflect.DeepEqual(actual, value) || len(decoder.data) != 0 {
			t.Fatal(fixture, actual, decoder.err)
		}
		decoder = tdsDecoder{data: append(metadata, 0)}
		if value := decoder.parameter(); decoder.err != nil || value != nil {
			t.Fatal("numeric NULL", fixture, value, decoder.err)
		}
	}
	// Golden signed-high/unsigned-low MONEY representation of its lower bound.
	value := int64(-9223372036854775808)
	if actual := tdsEncodeNumeric(tdsColumn{WireType: WireType{Kind: 0x6e, Size: 8}}, value); !bytes.Equal(actual, []byte{8, 0, 0, 0, 128, 0, 0, 0, 0}) {
		t.Fatalf("money high-low ordering %x", actual)
	}
	// A precision-38 value may use a shorter legal magnitude on input.
	decoder := tdsDecoder{data: []byte{0x6a, 17, 38, 0, 5, 1, 42, 0, 0, 0}}
	if value := decoder.parameter(); decoder.err != nil || value.(Decimal).Coefficient != "42" {
		t.Fatal(value, decoder.err)
	}
}

func TestTDSExactNumericMalformedValues(t *testing.T) {
	for _, fixture := range [][]byte{
		{0x6a, 17, 39, 0, 0}, {0x6a, 5, 9, 10, 0}, {0x6a, 7, 9, 0, 0},
		{0x6a, 5, 9, 0, 5, 2, 0, 0, 0, 0},
		{0x6a, 5, 9, 0, 9, 1, 1, 0, 0, 0, 0, 0, 0, 0}, {0x6a, 5, 9, 0, 5, 1, 1},
		{0x6e, 8, 4, 0, 0, 0, 0}, {0x6e, 3, 0},
	} {
		decoder := tdsDecoder{data: fixture}
		decoder.parameter()
		if decoder.err == nil {
			t.Fatalf("invalid numeric accepted %x", fixture)
		}
	}
	expectTDSPanic(t, func() {
		tdsEncodeNumeric(tdsColumn{WireType: WireType{Kind: 0x6a, Precision: 9, Scale: 2, Size: 5}}, float64(0.1))
	})
	expectTDSPanic(t, func() {
		tdsEncodeNumeric(tdsColumn{WireType: WireType{Kind: 0x6a, Precision: 9, Scale: 2, Size: 5}}, "0.1")
	})
	expectTDSPanic(t, func() {
		tdsEncodeNumeric(tdsColumn{WireType: WireType{Kind: 0x6a, Precision: 9, Scale: 2, Size: 5}}, Decimal{"4294967296"})
	})
}

// The explicit wire buffer may be wider than the minimum storage width for
// precision. Framework SqlClient always writes all four coefficient words.
func TestTDSNumericExplicitWiderBuffers(t *testing.T) {
	for _, kind := range []byte{0x6a, 0x6c} {
		for _, size := range []int{5, 9, 13, 17} {
			column := Column{WireType: WireType{Kind: kind, Size: size, Precision: 9, Scale: 2}}
			if !validType(column.WireType) {
				t.Fatal("legal explicit width rejected", column)
			}
			for _, coefficient := range []string{"0", "42", "-42", "999999999"} {
				value := Decimal{coefficient}
				encoded := tdsEncodeNumeric(column, value)
				if len(encoded) != size+1 || int(encoded[0]) != size {
					t.Fatalf("explicit width %d changed: %x", size, encoded)
				}
				metadata := []byte{kind, byte(size), 9, 2}
				decoder := tdsDecoder{data: append(metadata, encoded...)}
				actual := decoder.parameter()
				if decoder.err != nil || actual != value || decoder.descriptor != column.WireType || len(decoder.data) != 0 {
					t.Fatal("wider input changed its descriptor/value", actual, decoder.err)
				}
				decoder = tdsDecoder{data: append(metadata, 0)}
				if actual := decoder.parameter(); decoder.err != nil || actual != nil || decoder.descriptor != column.WireType || len(decoder.data) != 0 {
					t.Fatal("wider typed NULL changed", actual, decoder.err)
				}
			}
		}
	}
	// Independent 17-byte golden for a precision-18 coefficient, including sign.
	column := Column{WireType: WireType{Kind: 0x6c, Size: 17, Precision: 18}}
	want := []byte{17, 1, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if actual := tdsEncodeNumeric(column, Decimal{"42"}); !bytes.Equal(actual, want) {
		t.Fatalf("precision-18 wide golden: got %x want %x", actual, want)
	}
	for _, size := range []int{0, 1, 4, 6, 8, 12, 16, 18} {
		column.Size = size
		if validType(column.WireType) {
			t.Fatal("illegal explicit width accepted", size)
		}
	}
	column.Size = 5
	if validType(column.WireType) {
		t.Fatal("undersized metadata accepted for precision 18")
	}
}
