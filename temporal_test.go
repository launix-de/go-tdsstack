/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"reflect"
	"testing"
)

func TestTDSFractionalTimeAndLegacyDatetimeGoldens(t *testing.T) {
	for _, fixture := range []struct {
		payload   []byte
		column    tdsColumn
		kind      string
		day       int32
		ticks     uint64
		precision int
	}{
		{[]byte{0x29, 7, 5, 1, 0, 0, 0, 0}, tdsColumn{WireType: WireType{Kind: 0x29, Scale: 7}}, "TIME", 0, 1, 7},
		{[]byte{0x6f, 8, 8, 0, 0, 0, 0, 1, 0, 0, 0}, tdsColumn{WireType: WireType{Kind: 0x6f, Size: 8}}, "DATETIME", 0, 1, 3},
		{[]byte{0x6f, 8, 8, 255, 255, 255, 255, 43, 1, 0, 0}, tdsColumn{WireType: WireType{Kind: 0x6f, Size: 8}}, "DATETIME", -1, 299, 3},
	} {
		decoder := tdsDecoder{data: fixture.payload}
		value := decoder.parameter()
		day, ticks, offset := tdsTemporalParts(value)
		if decoder.err != nil || day != int64(fixture.day) || ticks != int64(fixture.ticks) || offset != 0 {
			t.Fatal(fixture, value, decoder.err)
		}
		if encoded := tdsEncodeTemporal(fixture.column, value); !bytes.Equal(encoded, fixture.payload[2:]) {
			t.Fatalf("fractional ticks changed %x != %x", encoded, fixture.payload[2:])
		}
	}
	value := tdsTemporalPayload(0, 1, 0)
	expectTDSPanic(t, func() { tdsEncodeTemporal(tdsColumn{WireType: WireType{Kind: 0x29, Scale: 8}}, value) })
	expectTDSPanic(t, func() {
		tdsEncodeTemporal(tdsColumn{WireType: WireType{Kind: 0x29, Scale: 7}}, tdsTemporalPayload(1, 1, 0))
	})
}

func TestTDSFractionalDatetime2RangesAndPrecision(t *testing.T) {
	for _, precision := range []int{1, 2, 3, 4, 5, 6, 7} {
		clock := uint64(13*3600+45*60+30)*tdsTimeFactor(byte(precision)) + 1
		value := tdsTemporalPayload(738944, int64(clock), 0)
		column := tdsColumn{WireType: WireType{Kind: 0x2a, Scale: byte(precision)}}
		encoded := tdsEncodeTemporal(column, value)
		decoder := tdsDecoder{data: append([]byte{0x2a, byte(precision)}, encoded...)}
		actual := decoder.parameter()
		day, ticks, offset := tdsTemporalParts(actual)
		if decoder.err != nil || day != 738944 || ticks != int64(clock) || offset != 0 {
			t.Fatal(precision, actual, decoder.err)
		}
	}
	value := tdsTemporalPayload(3652058, 86400*10000000-1, 0)
	encoded := tdsEncodeTemporal(tdsColumn{WireType: WireType{Kind: 0x2a, Scale: 7}}, value)
	decoder := tdsDecoder{data: append([]byte{0x2a, 7}, encoded...)}
	if actual := decoder.parameter(); decoder.err != nil || !reflect.DeepEqual(actual, value) {
		t.Fatal("upper endpoint", actual, decoder.err)
	}
	// Calendar/type-domain bounds are frontend policy. The wire adapter only
	// enforces packet field widths and preserves otherwise representable data.
	invalid := []byte{0x2a, 7, 8, 1}
	decoder = tdsDecoder{data: invalid}
	decoder.parameter()
	if decoder.err == nil {
		t.Fatal("truncated clock payload accepted")
	}

}

func TestTDSOffsetWirePreservesOriginalOffset(t *testing.T) {
	for _, offset := range []int64{-840, -60, 0, 90, 840} {
		payload := tdsTemporalPayload(738944, 123456789012, offset)
		column := tdsColumn{WireType: WireType{Kind: 0x2b, Scale: 7}}
		encoded := tdsEncodeTemporal(column, payload)
		decoder := tdsDecoder{data: append([]byte{0x2b, 7}, encoded...)}
		actual := decoder.parameter()
		if decoder.err != nil || !reflect.DeepEqual(actual, payload) {
			t.Fatal("offset payload changed", offset, decoder.err)
		}
		if len(encoded) != 11 {
			t.Fatal("offset wire width", len(encoded))
		}
	}
	for _, offset := range []int64{-32769, 32768} {
		expectTDSPanic(t, func() {
			tdsEncodeTemporal(tdsColumn{WireType: WireType{Kind: 0x2b, Scale: 7}}, tdsTemporalPayload(738944, 1, offset))
		})
	}
	decoder := tdsDecoder{data: []byte{0x2b, 7, 0}}
	if value := decoder.parameter(); decoder.err != nil || value != nil || decoder.descriptor.Kind != 0x2b || decoder.descriptor.Scale != 7 {
		t.Fatal("typed offset NULL lost descriptor", decoder.err)
	}
}
