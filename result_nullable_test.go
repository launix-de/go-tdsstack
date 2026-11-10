/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"testing"
)

// Independent byte goldens protect descriptor/ROW alignment, including clients
// that normalize nonnullable INTN/BITN/etc metadata into their fixed counterparts.
func TestNonnullableScalarResultGoldens(t *testing.T) {
	fixtures := []struct {
		name  string
		wire  WireType
		value any
		fixed byte
		data  []byte
	}{
		{"tinyint", WireType{Kind: 0x26, Size: 1}, int64(255), 0x30, []byte{255}},
		{"smallint", WireType{Kind: 0x26, Size: 2}, int64(-2), 0x34, []byte{254, 255}},
		{"int", WireType{Kind: 0x26, Size: 4}, int64(1024), 0x38, []byte{0, 4, 0, 0}},
		{"bigint", WireType{Kind: 0x26, Size: 8}, int64(-2), 0x7f, []byte{254, 255, 255, 255, 255, 255, 255, 255}},
		{"bit", WireType{Kind: 0x68, Size: 1}, true, 0x32, []byte{1}},
		{"real", WireType{Kind: 0x6d, Size: 4}, float64(1.5), 0x3b, []byte{0, 0, 192, 63}},
		{"float", WireType{Kind: 0x6d, Size: 8}, float64(1.5), 0x3e, []byte{0, 0, 0, 0, 0, 0, 248, 63}},
		{"smallmoney", WireType{Kind: 0x6e, Size: 4}, int64(-2), 0x7a, []byte{254, 255, 255, 255}},
		{"money", WireType{Kind: 0x6e, Size: 8}, int64(0x100000002), 0x3c, []byte{1, 0, 0, 0, 2, 0, 0, 0}},
		{"smalldatetime", WireType{Kind: 0x6f, Size: 4}, Temporal{Days: 2, Ticks: 3}, 0x3a, []byte{2, 0, 3, 0}},
		{"datetime", WireType{Kind: 0x6f, Size: 8}, Temporal{Days: -1, Ticks: 300}, 0x3d, []byte{255, 255, 255, 255, 44, 1, 0, 0}},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			for _, flags := range []uint16{0, 1, 0x2000} {
				var b bytes.Buffer
				r := &resultWriter{w: &b, ctx: context.Background()}
				column := Column{Name: "x", WireType: f.wire, Flags: flags}
				if err := r.Fields([]Column{column}); err != nil {
					t.Fatal(err)
				}
				if err := r.Row([]any{f.value}); err != nil {
					t.Fatal(err)
				}
				want := []byte{0x81, 1, 0, 0, 0, 0, 0, byte(flags), byte(flags >> 8)}
				if flags&1 == 0 {
					want = append(want, f.fixed)
				} else {
					want = append(want, f.wire.Kind, byte(f.wire.Size))
				}
				want = append(want, 1, 'x', 0, 0xd1)
				if flags&1 != 0 {
					want = append(want, byte(f.wire.Size))
				}
				want = append(want, f.data...)
				if !bytes.Equal(b.Bytes(), want) {
					t.Fatalf("flags=%x: got %x want %x", flags, b.Bytes(), want)
				}
				if column.Kind != f.wire.Kind || column.Flags != flags {
					t.Fatal("application descriptor changed")
				}
			}
			var b bytes.Buffer
			r := &resultWriter{w: &b}
			if err := r.Fields([]Column{{Name: "x", WireType: f.wire}}); err != nil {
				t.Fatal(err)
			}
			before := b.Len()
			if err := r.Row([]any{nil}); err == nil || b.Len() != before {
				t.Fatal("NULL fixed value accepted or partial ROW published")
			}
			var nullable bytes.Buffer
			r = &resultWriter{w: &nullable}
			if err := r.Fields([]Column{{Name: "x", WireType: f.wire, Flags: 1}}); err != nil {
				t.Fatal(err)
			}
			if err := r.Row([]any{nil}); err != nil {
				t.Fatal(err)
			}
			if !bytes.HasSuffix(nullable.Bytes(), []byte{0xd1, 0}) {
				t.Fatal("nullable NULL lost")
			}
		})
	}
}

// Result metadata and values must preserve the same application-selected
// numeric buffer. The transport must not silently normalize Size from Precision.
func TestNumericResultPreservesExplicitBuffer(t *testing.T) {
	for _, size := range []int{9, 17} {
		for _, kind := range []byte{0x6a, 0x6c} {
			var b bytes.Buffer
			r := &resultWriter{w: &b, ctx: context.Background()}
			columns := []Column{{Name: "n", WireType: WireType{Kind: kind, Size: size, Precision: 18}, Flags: 1}}
			if err := r.Fields(columns); err != nil {
				t.Fatal(err)
			}
			if err := r.Row([]any{Decimal{"42"}}); err != nil {
				t.Fatal(err)
			}
			if err := r.Row([]any{nil}); err != nil {
				t.Fatal(err)
			}
			want := []byte{0x81, 1, 0, 0, 0, 0, 0, 1, 0, kind, byte(size), 18, 0, 1, 'n', 0, 0xd1, byte(size), 1, 42}
			want = append(want, make([]byte, size-2)...)
			want = append(want, 0xd1, 0)
			if !bytes.Equal(b.Bytes(), want) || columns[0].Size != size || r.columns[0].Size != size {
				t.Fatalf("explicit numeric metadata/ROW changed: %x != %x", b.Bytes(), want)
			}
		}
	}
}
