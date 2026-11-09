/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"sync/atomic"
	"testing"

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
