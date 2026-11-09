/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// BulkReader streams one TDS 7.4 BulkLoadBCP message (MS-TDS 2.2.6.1).
// Columns returns explicit wire declarations. Next owns at most one bounded row;
// there is no message-sized buffer or SQL interpretation. It is request-local
// and must not be retained or used concurrently by the application's callback.
type BulkReader struct {
	columns  []Column
	ctx      context.Context
	d        tdsDecoder
	prefixes [][]byte
	complete bool
	rows     uint64
	failure  error
}

func newBulkReader(ctx context.Context, input io.Reader) (*BulkReader, error) {
	b := &BulkReader{ctx: ctx, d: tdsDecoder{reader: input, remaining: tdsMaxValue}}
	token := b.d.u8()
	if b.d.err != nil {
		return nil, b.d.err
	}
	if token != 0x81 {
		return nil, fmt.Errorf("bulk message requires COLMETADATA")
	}
	n := int(b.d.u16())
	if n == 0 || n > 4096 {
		return nil, fmt.Errorf("invalid bulk column count")
	}
	for i := 0; i < n; i++ {
		c := Column{UserType: b.d.u32(), Flags: b.d.u16()}
		kind := b.d.u8()
		c.Kind = kind
		fixed := 0
		var prefix bytes.Buffer
		prefix.WriteByte(kind)
		switch kind {
		case 0x30, 0x34, 0x38, 0x7f, 0x32, 0x3b, 0x3e, 0x7a, 0x3c, 0x3a, 0x3d:
			t := tdsFixedType(kind)
			fixed = t.Size
			c.WireType = t
			prefix.Reset()
			prefix.Write([]byte{t.Kind, byte(fixed), byte(fixed)})
		case 0x24, 0x26, 0x68, 0x6d, 0x6e, 0x6f:
			c.Size = int(b.d.u8())
			prefix.WriteByte(byte(c.Size))
		case 0x6a, 0x6c:
			c.Size = int(b.d.u8())
			c.Precision = b.d.u8()
			c.Scale = b.d.u8()
			prefix.Write([]byte{byte(c.Size), c.Precision, c.Scale})
		case 0x28:
		case 0x29, 0x2a, 0x2b:
			c.Scale = b.d.u8()
			prefix.WriteByte(c.Scale)
		case 0xa5, 0xad, 0xe7, 0xef, 0xa7, 0xaf:
			c.Size = int(b.d.u16())
			tdsU16(&prefix, uint16(c.Size))
			if kind != 0xa5 && kind != 0xad {
				copy(c.Collation[:], b.d.take(5))
				prefix.Write(c.Collation[:])
			}
		case 0x62:
			c.Size = int(b.d.u32())
			tdsU32(&prefix, uint32(c.Size))
		default:
			return nil, fmt.Errorf("unsupported bulk wire type 0x%02x", kind)
		}
		if b.d.err != nil {
			return nil, b.d.err
		}
		if !validType(c.WireType) {
			return nil, fmt.Errorf("invalid bulk wire descriptor")
		}
		c.Name = b.d.text(int(b.d.u8()))
		if b.d.err != nil {
			return nil, b.d.err
		}
		b.columns = append(b.columns, c)
		b.prefixes = append(b.prefixes, prefix.Bytes())
	}
	return b, nil
}

// Columns returns an owned copy. Fixed-width scalar wire tokens are normalized
// to their nullable descriptor equivalents without changing their payloads.
func (b *BulkReader) Columns() []Column { return append([]Column(nil), b.columns...) }

// Fixed tokens and their nullable wire equivalents have identical scalar
// payloads. Normalization preserves exact widths and does not infer SQL types.
func tdsFixedType(kind byte) WireType {
	t := WireType{Kind: 0x26}
	switch kind {
	case 0x30:
		t.Size = 1
	case 0x34:
		t.Size = 2
	case 0x38:
		t.Size = 4
	case 0x7f:
		t.Size = 8
	case 0x32:
		t.Kind = 0x68
		t.Size = 1
	case 0x3b:
		t.Kind = 0x6d
		t.Size = 4
	case 0x3e:
		t.Kind = 0x6d
		t.Size = 8
	case 0x7a:
		t.Kind = 0x6e
		t.Size = 4
	case 0x3c:
		t.Kind = 0x6e
		t.Size = 8
	case 0x3a:
		t.Kind = 0x6f
		t.Size = 4
	case 0x3d:
		t.Kind = 0x6f
		t.Size = 8
	}
	return t
}

// Next returns io.EOF only after DONE and the complete message boundary were
// validated. Applications must treat every other error as a failed import and
// roll back their pending writes, including rows already delivered.
func (b *BulkReader) Next() ([]any, error) {
	if b.failure != nil {
		return nil, b.failure
	}
	row, err := b.next()
	if err == io.EOF && !b.complete {
		err = io.ErrUnexpectedEOF
	}
	if err != nil && err != io.EOF {
		b.failure = err
	}
	return row, err
}

func (b *BulkReader) next() ([]any, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if b.complete {
		return nil, io.EOF
	}
	b.d.remaining = tdsMaxValue
	token := b.d.u8()
	if b.d.err != nil {
		return nil, b.d.err
	}
	switch token {
	case 0xfd:
		status := b.d.u16()
		b.d.u16() // CurCmd is reserved for the sender's command identification.
		if b.d.err != nil {
			return nil, b.d.err
		}
		var countBytes [8]byte
		n, countErr := io.ReadFull(b.d.reader, countBytes[:])
		// Framework SqlClient WriteBulkCopyDone emits a 32-bit zero count
		// even on TDS 7.4. Accept only that exact no-count form at a proven
		// message boundary, never arbitrary truncated or nonzero counts.
		short := n == 4 && countErr == io.ErrUnexpectedEOF && status == 0 &&
			binary.LittleEndian.Uint32(countBytes[:4]) == 0
		if countErr != nil && !short {
			return nil, countErr
		}
		count := binary.LittleEndian.Uint64(countBytes[:])
		if status & ^uint16(0x10) != 0 || status&0x10 != 0 && count != b.rows {
			return nil, fmt.Errorf("invalid bulk DONE")
		}
		var extra [1]byte
		n, err := b.d.reader.Read(extra[:])
		if n != 0 || err != io.EOF {
			return nil, fmt.Errorf("bulk message has no clean end (%v)", err)
		}
		b.complete = true
		return nil, io.EOF
	case 0xd1:
		values := make([]any, len(b.columns))
		for i := range values {
			decoder := tdsDecoder{reader: io.MultiReader(bytes.NewReader(b.prefixes[i]), b.d.reader), remaining: b.d.remaining}
			values[i] = decoder.parameter()
			b.d.remaining = decoder.remaining
			if decoder.err != nil {
				return nil, decoder.err
			}
		}
		b.rows++
		return values, nil
	default:
		return nil, fmt.Errorf("unsupported bulk token 0x%02x", token)
	}
}

// bulkPackets exposes a single bounded packet at a time. It never consumes
// bytes from the following request. IGNORE/RESET flags fail the message so an
// aborted input cannot be mistaken for an ordinary end and committed. Unused
// status bits (including Framework's ST_BATCH) are ignored per MS-TDS 2.2.3.1.2.
type bulkPackets struct {
	r               io.Reader
	left            int
	final, complete bool
}

func (p *bulkPackets) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	for p.left == 0 {
		if p.final || p.complete {
			p.complete = true
			return 0, io.EOF
		}
		var header [8]byte
		if _, err := io.ReadFull(p.r, header[:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		p.left = int(binary.BigEndian.Uint16(header[2:4])) - 8
		if header[0] != 7 || header[1]&0x1a != 0 || p.left < 0 || p.left == 0 && header[1]&1 == 0 {
			return 0, fmt.Errorf("invalid bulk packet header")
		}
		p.final = header[1]&1 != 0
	}
	if len(dst) > p.left {
		dst = dst[:p.left]
	}
	n, err := p.r.Read(dst)
	p.left -= n
	if err == io.EOF && (p.left != 0 || !p.final) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
