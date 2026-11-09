/*
	Copyright (C) 2026 Carl-Philip Hänsch

SPDX-License-Identifier: GPL-3.0-or-later
*/
package tds

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type diagnosticShortWriter struct{ bytes.Buffer }

func (w *diagnosticShortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}
func TestErrorDiagnosticEncodingBounds(t *testing.T) {
	name := strings.Repeat("🙂", 127) + "x"
	for _, d := range []Message{
		{Number: 8115, State: 255, Severity: 255, Text: "failure Grüße 🙂", Server: name, Procedure: name, Line: 0xffffffff},
		{Text: strings.Repeat("x", 32760)},
		{Text: strings.Repeat("🙂", 16380)},
		{Text: strings.Repeat("x", 32250), Server: name, Procedure: name},
	} {
		data, err := tdsDiagnostic(0xaa, d)
		info, infoErr := tdsDiagnostic(0xab, d)
		if err != nil || infoErr != nil || data[0] != 0xaa || info[0] != 0xab || !bytes.Equal(data[1:], info[1:]) ||
			int(binary.LittleEndian.Uint16(data[1:3])) != len(data)-3 {
			t.Fatal("diagnostic kinds disagree about bounded framing", len(data), err, infoErr)
		}
		var short diagnosticShortWriter
		if err := tdsWriteAll(&short, data); err != nil || !bytes.Equal(short.Bytes(), data) {
			t.Fatal("short writes changed diagnostic framing", err)
		}
	}
	for _, d := range []Message{
		{Text: strings.Repeat("x", 32761)}, {Text: strings.Repeat("🙂", 16381)},
		{Text: strings.Repeat("x", 32760), Server: "x"},
		{Text: strings.Repeat("x", 32251), Server: name, Procedure: name},
		{Server: strings.Repeat("🙂", 128)}, {Procedure: strings.Repeat("🙂", 128)},
		{Server: strings.Repeat("x", 256)}, {Procedure: strings.Repeat("x", 256)},
		{Text: string([]byte{0xff})}, {Server: string([]byte{0xff})}, {Procedure: string([]byte{0xff})},
	} {
		if data, err := tdsDiagnostic(0xaa, d); err == nil || len(data) != 0 {
			t.Fatal("invalid error diagnostic published partial framing", len(data), err)
		}
	}
}

func TestOrdinaryErrorRetainsBoundedDefaults(t *testing.T) {
	for _, message := range []string{"ordinary failure", strings.Repeat("x", 2047) + "🙂", string([]byte{0xff})} {
		d := tdsDefaultDiagnostic(50000, message)
		if d.Number != 50000 || d.State != 1 || d.Severity != 16 || d.Server != "TDS" || d.Procedure != "" || d.Line != 1 || len(d.Text) > 2048 {
			t.Fatal("ordinary error defaults changed", d)
		}
		if _, err := tdsDiagnostic(0xaa, d); err != nil {
			t.Fatal("ordinary error no longer has valid framing", err)
		}
	}
	data, err := tdsDiagnostic(0xaa, tdsDefaultDiagnostic(50000, "failure"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tdsWriteAll(zeroWriter{}, data); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("error token lost failed write", err)
	}
}

// These literal fixtures keep GUID byte order independent of the value encoder.
