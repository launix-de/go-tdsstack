/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"fmt"
	"strings"
)

// MS-TDS 2.2.5.5.4 uses fixed-width base tokens rather than the ordinary nullable
// descriptors. Keep normalization at the wire boundary; application types remain
// explicit and match those accepted for standalone values.
func variantBase(t WireType) (byte, []byte, int) {
	if !validType(t) {
		panic("invalid sql_variant base descriptor")
	}
	switch t.Kind {
	case 0x26:
		return map[int]byte{1: 0x30, 2: 0x34, 4: 0x38, 8: 0x7f}[t.Size], nil, 1
	case 0x68:
		return 0x32, nil, 1
	case 0x6d:
		if t.Size == 4 {
			return 0x3b, nil, 1
		}
		return 0x3e, nil, 1
	case 0x6e:
		if t.Size == 4 {
			return 0x7a, nil, 1
		}
		return 0x3c, nil, 1
	case 0x6f:
		if t.Size == 4 {
			return 0x3a, nil, 1
		}
		return 0x3d, nil, 1
	case 0x28:
		return t.Kind, nil, 1
	case 0x29, 0x2a, 0x2b:
		return t.Kind, []byte{t.Scale}, 1
	case 0x6a, 0x6c:
		return t.Kind, []byte{t.Precision, t.Scale}, 1
	case 0xa5, 0xad, 0xa7, 0xaf, 0xe7, 0xef:
		if t.Size > 8000 || (t.Kind == 0xe7 || t.Kind == 0xef) && t.Size%2 != 0 {
			panic("sql_variant excludes MAX/oversized base widths")
		}
		var props bytes.Buffer
		if t.Kind != 0xa5 && t.Kind != 0xad {
			props.Write(t.Collation[:])
		}
		tdsU16(&props, uint16(t.Size))
		return t.Kind, props.Bytes(), 2
	default:
		panic("unsupported sql_variant base type")
	}
}

func tdsEncodeVariant(column Column, value any) []byte {
	var result bytes.Buffer
	if value == nil {
		tdsU32(&result, 0)
		return result.Bytes()
	}
	variant, ok := value.(Variant)
	if !ok || variant.Value == nil {
		panic("sql_variant requires a non-NULL Variant payload")
	}
	base, properties, prefix := variantBase(variant.Type)
	encoded := encodeWireValue(Column{WireType: variant.Type}, variant.Value)
	payload := encoded[prefix:]
	// SQL_VARIANT numerics use a 16-byte magnitude even when the declared
	// precision would use a shorter ordinary NUMERICN value.
	if base == 0x6a || base == 0x6c {
		coefficient := variant.Value.(Decimal).Coefficient
		if len(strings.TrimPrefix(coefficient, "-")) > int(variant.Type.Precision) {
			panic("sql_variant numeric precision overflow")
		}
		full := make([]byte, 17)
		copy(full, payload)
		payload = full
	}
	size := 2 + len(properties) + len(payload)
	if len(payload) > 8000 || size > column.Size || size > 8016 {
		panic("sql_variant payload exceeds declared width")
	}
	tdsU32(&result, uint32(size))
	result.WriteByte(base)
	result.WriteByte(byte(len(properties)))
	result.Write(properties)
	result.Write(payload)
	return result.Bytes()
}

func (d *tdsDecoder) variant() any {
	maxSize, size := d.u32(), d.u32()
	d.descriptor = WireType{Kind: 0x62, Size: int(maxSize)}
	if maxSize == 0 || maxSize > 8016 || size > maxSize {
		d.err = fmt.Errorf("invalid sql_variant outer length")
		return nil
	}
	if size == 0 {
		return nil
	}
	instance := tdsDecoder{data: d.take(int(size))}
	base, count := instance.u8(), int(instance.u8())
	properties := instance.take(count)
	payload := instance.data
	if d.err != nil {
		return nil
	}
	if instance.err != nil || len(payload) > 8000 {
		d.err = fmt.Errorf("truncated or oversized sql_variant instance")
		return nil
	}
	var ordinary bytes.Buffer
	var expected int
	var declaredNumeric WireType
	switch base {
	case 0x30, 0x34, 0x38, 0x7f, 0x32, 0x3b, 0x3e, 0x7a, 0x3c, 0x3a, 0x3d:
		kind, width := byte(0x26), 0
		switch base {
		case 0x30:
			width = 1
		case 0x34:
			width = 2
		case 0x38:
			width = 4
		case 0x7f:
			width = 8
		case 0x32:
			kind, width = 0x68, 1
		case 0x3b:
			kind, width = 0x6d, 4
		case 0x3e:
			kind, width = 0x6d, 8
		case 0x7a:
			kind, width = 0x6e, 4
		case 0x3c:
			kind, width = 0x6e, 8
		case 0x3a:
			kind, width = 0x6f, 4
		case 0x3d:
			kind, width = 0x6f, 8
		}
		if len(payload) != width {
			d.err = fmt.Errorf("invalid sql_variant scalar width")
			return nil
		}
		ordinary.Write([]byte{kind, byte(width), byte(width)})
	case 0x28:
		ordinary.Write([]byte{base, byte(len(payload))})
	case 0x29, 0x2a, 0x2b:
		expected = 1
		if count == expected {
			ordinary.Write([]byte{base, properties[0], byte(len(payload))})
		}
	case 0x6a, 0x6c:
		expected = 2
		if count == expected && properties[0] >= 1 && properties[0] <= 38 && properties[1] <= properties[0] && len(payload) == 17 {
			declaredNumeric = WireType{Kind: base, Size: tdsDecimalSize(int(properties[0])), Precision: properties[0], Scale: properties[1]}
			ordinary.Write([]byte{base, 17, 38, properties[1], 17})
		}
	case 0xa5, 0xad, 0xa7, 0xaf, 0xe7, 0xef:
		expected = 2
		if base != 0xa5 && base != 0xad {
			expected = 7
		}
		if count == expected {
			ordinary.WriteByte(base)
			ordinary.Write(properties[count-2:])
			if expected == 7 {
				ordinary.Write(properties[:5])
			}
			tdsU16(&ordinary, uint16(len(payload)))
		}
	default:
		d.err = fmt.Errorf("unsupported sql_variant base type 0x%02x", base)
		return nil
	}
	if count != expected || ordinary.Len() == 0 {
		d.err = fmt.Errorf("invalid sql_variant properties")
		return nil
	}
	ordinary.Write(payload)
	decoded := tdsDecoder{data: ordinary.Bytes()}
	value := decoded.parameter()
	if decoded.err != nil || len(decoded.data) != 0 || value == nil {
		d.err = fmt.Errorf("invalid sql_variant base payload: %v", decoded.err)
		return nil
	}
	if declaredNumeric.Kind != 0 {
		if len(strings.TrimPrefix(value.(Decimal).Coefficient, "-")) > int(declaredNumeric.Precision) {
			d.err = fmt.Errorf("sql_variant numeric precision overflow")
			return nil
		}
		decoded.descriptor = declaredNumeric
	}
	// The same descriptor validation excludes illegal MAX lengths and widths on
	// input as on output, rather than accepting malformed dynamic metadata.
	if err := catchWire(func() { variantBase(decoded.descriptor) }); err != nil {
		d.err = err
		return nil
	}
	if count == 7 {
		copy(decoded.descriptor.Collation[:], properties[:5])
	}
	return Variant{Type: decoded.descriptor, Value: value}
}
