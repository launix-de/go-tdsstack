/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

func tdsDecimalSize(precision int) int {
	switch {
	case precision >= 1 && precision <= 9:
		return 5
	case precision >= 10 && precision <= 19:
		return 9
	case precision >= 20 && precision <= 28:
		return 13
	case precision >= 29 && precision <= 38:
		return 17
	default:
		panic("invalid TDS coefficient width")
	}
}

// Wire decoding produces an unscaled coefficient. Frontend callbacks receive
// the complete descriptor, including for NULL, and choose its interpretation.
func (d *tdsDecoder) numeric(kind byte) (value any) {
	defer func() {
		if failure := recover(); failure != nil {
			d.err = fmt.Errorf("invalid TDS coefficient: %v", failure)
			value = nil
		}
	}()
	maxSize := int(d.u8())
	d.descriptor = WireType{Kind: kind, Size: maxSize}
	if kind == 0x6a || kind == 0x6c {
		precision, scale := int(d.u8()), int(d.u8())
		if precision < 1 || precision > 38 || scale < 0 || scale > precision || maxSize != tdsDecimalSize(precision) {
			d.err = fmt.Errorf("invalid TDS coefficient metadata")
			return nil
		}
		d.descriptor.Precision, d.descriptor.Scale = byte(precision), byte(scale)
		n := int(d.u8())
		if n == 0 {
			return nil
		}
		if (n != 5 && n != 9 && n != 13 && n != 17) || n > maxSize {
			d.err = fmt.Errorf("invalid TDS coefficient length")
			return nil
		}
		sign := d.u8()
		if sign > 1 {
			d.err = fmt.Errorf("invalid TDS coefficient sign")
			return nil
		}
		magnitude := d.take(n - 1)
		if d.err != nil {
			return nil
		}
		reversed := make([]byte, len(magnitude))
		for i, b := range magnitude {
			reversed[len(magnitude)-1-i] = b
		}
		integer := new(big.Int).SetBytes(reversed)
		if sign == 0 {
			integer.Neg(integer)
		}
		return Decimal{Coefficient: integer.String()}
	}
	n := int(d.u8())
	if (maxSize != 4 && maxSize != 8) || (n != 0 && n != maxSize) {
		d.err = fmt.Errorf("invalid TDS high-low integer length")
		return nil
	}
	if n == 0 {
		return nil
	}
	raw := d.take(n)
	if d.err != nil {
		return nil
	}
	if n == 4 {
		return int64(int32(binary.LittleEndian.Uint32(raw)))
	}
	return int64(binary.LittleEndian.Uint32(raw))<<32 | int64(binary.LittleEndian.Uint32(raw[4:]))
}

// The caller supplies a coefficient already converted to the descriptor's
// scale. No cast, inferred type, or precision propagation occurs here.
func tdsEncodeNumeric(column tdsColumn, value any) []byte {
	if value == nil {
		return []byte{0}
	}
	if column.Kind == 0x6e {
		if !isInt64(value) || (column.Size != 4 && column.Size != 8) {
			panic("TDS high-low integer requires an integer payload")
		}
		integer := value.(int64)
		if column.Size == 4 && (integer < -2147483648 || integer > 2147483647) {
			panic("TDS signed 32-bit payload overflow")
		}
		encoded := make([]byte, 1+column.Size)
		encoded[0] = byte(column.Size)
		if column.Size == 4 {
			binary.LittleEndian.PutUint32(encoded[1:], uint32(integer))
		} else {
			binary.LittleEndian.PutUint32(encoded[1:], uint32(uint64(integer)>>32))
			binary.LittleEndian.PutUint32(encoded[5:], uint32(integer))
		}
		return encoded
	}
	decimal, ok := value.(Decimal)
	if !ok {
		panic("numeric wire value requires a Decimal coefficient")
	}
	integer, ok := new(big.Int).SetString(decimal.Coefficient, 10)
	if !ok || integer.String() != decimal.Coefficient {
		panic("invalid canonical coefficient")
	}
	negative := integer.Sign() < 0
	integer.Abs(integer)
	size := tdsDecimalSize(int(column.Precision))
	if integer.BitLen() > (size-1)*8 {
		panic("TDS coefficient exceeds wire width")
	}
	encoded := make([]byte, size+1)
	encoded[0], encoded[1] = byte(size), 1
	if negative {
		encoded[1] = 0
	}
	magnitude := integer.Bytes()
	for i, b := range magnitude {
		encoded[2+len(magnitude)-1-i] = b
	}
	return encoded
}
