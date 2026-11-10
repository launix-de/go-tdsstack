/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"

	driver "github.com/denisenkom/go-mssqldb"
)

func bulkFixture() []byte {
	var b bytes.Buffer
	b.WriteByte(0x81)
	tdsU16(&b, 2)
	for _, c := range []Column{
		{Name: "id", WireType: WireType{Kind: 0x26, Size: 4}},
		{Name: "text", WireType: WireType{Kind: 0xe7, Size: 65535}, Flags: 1},
	} {
		tdsU32(&b, 0)
		tdsU16(&b, c.Flags)
		b.WriteByte(c.Kind)
		if c.Kind == 0x26 {
			b.WriteByte(4)
		} else {
			tdsU16(&b, 65535)
			b.Write(make([]byte, 5))
		}
		tdsBText(&b, c.Name)
	}
	b.WriteByte(0xd1)
	b.Write(encodeWireValue(Column{WireType: WireType{Kind: 0x26, Size: 4}}, int64(42)))
	b.Write(encodeWireValue(Column{WireType: WireType{Kind: 0xe7, Size: 65535}}, "Grüße 🙂"))
	tdsDone(&b, 0xfd, 0x10, 1)
	return b.Bytes()
}

func TestBulkValidatedEnd(t *testing.T) {
	fixture := bulkFixture()
	for _, name := range []string{"complete", "missing-done", "trailing", "done-error", "bad-count", "truncated-value"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), fixture...)
			switch name {
			case "missing-done":
				data = data[:len(data)-13]
			case "trailing":
				data = append(data, 0)
			case "done-error":
				data[len(data)-12] = 2
			case "bad-count":
				binary.LittleEndian.PutUint64(data[len(data)-8:], 99)
			case "truncated-value":
				data = data[:len(data)-20]
			}
			b, err := newBulkReader(context.Background(), bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			row, err := b.Next()
			if name == "truncated-value" {
				if err == nil || err == io.EOF {
					t.Fatalf("truncated row must fail, got %v", err)
				}
				return
			}
			if err != nil || len(row) != 2 || row[0] != int64(42) || row[1] != "Grüße 🙂" {
				t.Fatalf("row %v: %v", row, err)
			}
			_, err = b.Next()
			if name == "complete" {
				if err != io.EOF || !b.complete {
					t.Fatalf("expected validated EOF: %v", err)
				}
			} else {
				if err == nil || err == io.EOF || b.complete {
					t.Fatalf("malformed message accepted: %v", err)
				}
				_, again := b.Next()
				if again != err {
					t.Fatalf("failed stream resumed: %v then %v", err, again)
				}
			}
		})
	}
}

func TestBulkPacketBoundary(t *testing.T) {
	for _, name := range []string{"complete", "truncated-packet", "missing-eom", "ignore", "wrong-kind"} {
		t.Run(name, func(t *testing.T) {
			var message bytes.Buffer
			if err := writeTDSMessage(&message, 7, bulkFixture()); err != nil {
				t.Fatal(err)
			}
			wire := message.Bytes()
			switch name {
			case "truncated-packet":
				binary.BigEndian.PutUint16(wire[2:4], uint16(len(wire)+1))
			case "missing-eom":
				wire[1] = 0
			case "ignore":
				wire[1] |= 2
			case "wrong-kind":
				wire[0] = 1
			}
			b, err := newBulkReader(context.Background(), &bulkPackets{r: bytes.NewReader(wire)})
			if err == nil {
				_, err = b.Next()
				if err == nil {
					_, err = b.Next()
				}
			}
			if name == "complete" {
				if err != io.EOF || !b.complete {
					t.Fatal(err)
				}
			} else if err == nil || err == io.EOF {
				t.Fatalf("bad packet accepted: %v", err)
			}
		})
	}
}

func TestBulkReleasedClientStreaming(t *testing.T) {
	var committed atomic.Uint64
	db, _, _ := startClient(t, false, func(s *Server) {
		s.Handler.Execute = func(_ context.Context, _ Session, r Request, w ResultWriter) error {
			if strings.HasPrefix(r.Text, "select * from") {
				return w.Fields([]Column{fixtureColumn("v", 0xe7, 65535)})
			}
			return nil // Opaque fixture text: no application SQL semantics.
		}
		s.Handler.Bulk = func(_ context.Context, _ Session, b *BulkReader) (Completion, error) {
			var count uint64
			for {
				row, err := b.Next()
				if err == io.EOF {
					committed.Store(count)
					return Completion{Rows: count}, nil
				}
				if err != nil {
					return Completion{}, err
				}
				if len(row) != 1 || row[0] != strings.Repeat("🙂", 4096) {
					return Completion{}, io.ErrUnexpectedEOF
				}
				count++
			}
		}
	})
	// More than the ordinary 16 MiB message bound; packet backpressure keeps
	// the transport's retained input independent of the number of rows.
	stmt, err := db.Prepare(driver.CopyIn("fixture", driver.BulkOptions{}, "v"))
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	text := strings.Repeat("🙂", 4096)
	for i := 0; i < 1100; i++ {
		if _, err = stmt.Exec(text); err != nil {
			t.Fatal(err)
		}
	}
	result, err := stmt.Exec()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1100 || committed.Load() != 1100 {
		t.Fatalf("rows %d committed %d: %v", rows, committed.Load(), err)
	}
}

// Framework SqlClient uses a 32-bit zero DONE count even after a TDS 7.4 login.
// This exception must never turn other truncation or following requests into EOF.
func TestBulkFrameworkShortDone(t *testing.T) {
	prefix := bulkFixture()
	prefix = prefix[:len(prefix)-13]
	for _, fixture := range []struct {
		name   string
		status uint16
		count  []byte
		valid  bool
	}{
		{"framework", 0, make([]byte, 4), true},
		{"count0", 0, nil, false}, {"count1", 0, make([]byte, 1), false},
		{"count2", 0, make([]byte, 2), false}, {"count3", 0, make([]byte, 3), false},
		{"count5", 0, make([]byte, 5), false}, {"count6", 0, make([]byte, 6), false},
		{"count7", 0, make([]byte, 7), false}, {"nonzero", 0, []byte{1, 0, 0, 0}, false},
		{"countflag", 0x10, make([]byte, 4), false}, {"errorflag", 2, make([]byte, 4), false},
		{"full", 0, make([]byte, 8), true}, {"trailing", 0, make([]byte, 9), false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var payload, packets bytes.Buffer
			payload.Write(prefix)
			payload.WriteByte(0xfd)
			tdsU16(&payload, fixture.status)
			tdsU16(&payload, 0)
			payload.Write(fixture.count)
			if err := writeTDSMessage(&packets, 7, payload.Bytes()); err != nil {
				t.Fatal(err)
			}
			next := []byte("following request must remain untouched")
			packets.Write(next)
			reader := bytes.NewReader(packets.Bytes())
			b, err := newBulkReader(context.Background(), &bulkPackets{r: reader})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.Next(); err != nil {
				t.Fatal(err)
			}
			_, err = b.Next()
			if fixture.valid {
				if err != io.EOF || !b.complete {
					t.Fatalf("valid DONE rejected: %v", err)
				}
			} else if err == nil || err == io.EOF || b.complete {
				t.Fatalf("malformed DONE accepted: %v", err)
			}
			remaining, _ := io.ReadAll(reader)
			if !bytes.Equal(remaining, next) {
				t.Fatalf("following request consumed: %q", remaining)
			}
		})
	}
}

// Wide metadata, one row and DONE each span packet boundaries. The last value
// positions DONE so its count is split between packets, never a message boundary.
func wideBulkFixture() ([]byte, []any) {
	var b bytes.Buffer
	b.WriteByte(0x81)
	tdsU16(&b, 224)
	for i := 0; i < 224; i++ {
		tdsU32(&b, 0)
		tdsU16(&b, 1)
		b.WriteByte(0xe7)
		tdsU16(&b, 4000)
		b.Write([]byte{9, 4, 0xd0, 0, 52})
		tdsBText(&b, fmt.Sprintf("column_%03d", i))
	}
	values := make([]any, 224)
	b.WriteByte(0xd1)
	for i := range values {
		value := fmt.Sprintf("v_%03d", i)
		if i == len(values)-1 {
			// Its own length prefix and UTF-16 value are still to be written.
			beforeDone := b.Len() + 2 + len(tdsUTF16(value))
			padding := (tdsPacketSize - 14 - beforeDone%(tdsPacketSize-8) + (tdsPacketSize - 8)) % (tdsPacketSize - 8)
			value += strings.Repeat("x", padding/2)
		}
		values[i] = value
		b.Write(encodeWireValue(Column{WireType: WireType{Kind: 0xe7, Size: 4000}}, value))
	}
	tdsDone(&b, 0xfd, 0x10, 1)
	return b.Bytes(), values
}

func TestBulkContinuationStatusAndFraming(t *testing.T) {
	payload, want := wideBulkFixture()
	for _, name := range []string{"normal", "batch", "batch-final", "reserved", "ignore-first", "ignore-continuation", "reset", "reset-continuation", "reset-preserve", "truncated-header", "truncated-payload", "missing-eom", "wrong-continuation-kind"} {
		t.Run(name, func(t *testing.T) {
			var packets bytes.Buffer
			if err := writeTDSMessage(&packets, 7, payload); err != nil {
				t.Fatal(err)
			}
			wire := append([]byte(nil), packets.Bytes()...)
			offsets := []int{}
			for at := 0; at < len(wire); {
				offsets = append(offsets, at)
				at += int(binary.BigEndian.Uint16(wire[at+2:]))
			}
			if len(offsets) < 4 {
				t.Fatal("fixture no longer crosses metadata, row and DONE packet boundaries")
			}
			for _, at := range offsets {
				if wire[at+1]&1 == 0 {
					wire[at+1] |= 4
				}
			}
			valid := false
			switch name {
			case "normal":
				for _, at := range offsets {
					wire[at+1] &^= 4
				}
				valid = true
			case "batch":
				valid = true
			case "batch-final":
				wire[offsets[len(offsets)-1]+1] |= 4
				valid = true
			case "reserved":
				for _, at := range offsets {
					wire[at+1] |= 0xe0
				}
				valid = true
			case "ignore-first":
				wire[1] |= 2
			case "ignore-continuation":
				wire[offsets[1]+1] |= 2
			case "reset":
				wire[1] |= 8
			case "reset-continuation":
				wire[offsets[1]+1] |= 8
			case "reset-preserve":
				wire[1] |= 16
			case "truncated-header":
				wire = wire[:offsets[len(offsets)-1]+4]
			case "truncated-payload":
				wire = wire[:len(wire)-1]
			case "missing-eom":
				wire[offsets[len(offsets)-1]+1] &^= 1
			case "wrong-continuation-kind":
				wire[offsets[1]] = 1
			}
			following := []byte("following request")
			completeWire := append(append([]byte(nil), wire...), following...)
			// Truncation tests use actual EOF so bytes from another request cannot
			// accidentally fill a deliberately truncated packet in the fixture.
			if name == "truncated-header" || name == "truncated-payload" || name == "missing-eom" {
				completeWire = wire
			}
			reader := bytes.NewReader(completeWire)
			bulk, err := newBulkReader(context.Background(), &bulkPackets{r: reader})
			if err == nil {
				var row []any
				row, err = bulk.Next()
				if err == nil && valid && !reflect.DeepEqual(row, want) {
					t.Fatal("packet boundary changed row", len(row))
				}
				if err == nil {
					_, err = bulk.Next()
				}
			}
			if valid {
				if err != io.EOF || !bulk.complete {
					t.Fatal("valid batch framing rejected", err)
				}
				if len(bulk.Columns()) != 224 || bulk.Columns()[223].Name != "column_223" {
					t.Fatal("wide metadata changed")
				}
				rest, _ := io.ReadAll(reader)
				if !bytes.Equal(rest, following) {
					t.Fatal("following request consumed", string(rest))
				}
			} else if err == nil || err == io.EOF {
				t.Fatal("malformed packet accepted", err)
			}
			if name == "ignore-first" || name == "reset" || name == "reset-preserve" {
				if err == nil || !strings.Contains(err.Error(), "invalid bulk packet header") {
					t.Fatal("header error masked", err)
				}
			}
		})
	}
}

// Independently authored mixed ROW bytes expose a coefficient-width mismatch:
// a sender that claims nine bytes but emits seventeen must never reach EOF.
func TestBulkNumericExplicitWidthAndFollowingRows(t *testing.T) {
	for _, kind := range []byte{0x6a, 0x6c} {
		for _, fixture := range []struct {
			name              string
			declared, emitted int
			valid             bool
		}{
			{"compact", 9, 9, true},
			{"framework-wide", 17, 17, true},
			{"wrong-value-length", 9, 17, false},
			{"truncated-wide", 17, 9, false},
		} {
			t.Run(fmt.Sprintf("%x/%s", kind, fixture.name), func(t *testing.T) {
				var b bytes.Buffer
				// COLMETADATA: fixed INT followed by nullable NUMERIC(18,0).
				b.Write([]byte{0x81, 2, 0, 0, 0, 0, 0, 0, 0, 0x38, 1, 'i', 0})
				b.Write([]byte{0, 0, 0, 0, 1, 0, kind, byte(fixture.declared), 18, 0, 1, 'n', 0})
				b.Write([]byte{0xd1, 1, 0, 0, 0, byte(fixture.declared), 1, 42})
				b.Write(make([]byte, fixture.emitted-2))
				if fixture.name != "truncated-wide" {
					b.Write([]byte{0xd1, 2, 0, 0, 0, 0}) // Numeric NULL, next row.
					tdsDone(&b, 0xfd, 0x10, 2)
				}
				bulk, err := newBulkReader(context.Background(), iotest.OneByteReader(bytes.NewReader(b.Bytes())))
				if err != nil {
					t.Fatal(err)
				}
				if columns := bulk.Columns(); len(columns) != 2 || columns[1].Size != fixture.declared || columns[1].Precision != 18 {
					t.Fatal("explicit bulk metadata changed", columns)
				}
				first, err := bulk.Next()
				if err == nil && fixture.valid && !reflect.DeepEqual(first, []any{int64(1), Decimal{"42"}}) {
					t.Fatal("first row changed", first)
				}
				var second []any
				if err == nil {
					second, err = bulk.Next()
				}
				if err == nil && fixture.valid && !reflect.DeepEqual(second, []any{int64(2), nil}) {
					t.Fatal("following row/NULL changed", second)
				}
				if err == nil {
					_, err = bulk.Next()
				}
				if fixture.valid {
					if err != io.EOF || !bulk.complete {
						t.Fatal("valid stream did not complete", err)
					}
				} else {
					if err == nil || err == io.EOF || bulk.complete {
						t.Fatal("malformed coefficient completed", err)
					}
					if _, repeated := bulk.Next(); repeated != err {
						t.Fatal("malformed stream lost sticky failure", repeated, err)
					}
				}
			})
		}
	}
}
