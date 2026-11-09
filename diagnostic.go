/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// INFO and ERROR have the same bounded UTF-16 payload. Build the complete token
// before publication, retaining application metadata without SQL classification.
func tdsDiagnostic(kind byte, message Message) ([]byte, error) {
	if len(message.Text) > 2*math.MaxUint16 || len(message.Server) > 4*math.MaxUint8 || len(message.Procedure) > 4*math.MaxUint8 ||
		!utf8.ValidString(message.Text) || !utf8.ValidString(message.Server) || !utf8.ValidString(message.Procedure) {
		return nil, fmt.Errorf("invalid or oversized diagnostic text")
	}
	text, server, procedure := tdsUTF16(message.Text), tdsUTF16(message.Server), tdsUTF16(message.Procedure)
	length := 14 + len(text) + len(server) + len(procedure)
	if length > math.MaxUint16 || len(server)/2 > math.MaxUint8 || len(procedure)/2 > math.MaxUint8 {
		return nil, fmt.Errorf("diagnostic fields exceed wire length limits")
	}
	var payload bytes.Buffer
	payload.Grow(length)
	tdsU32(&payload, message.Number)
	payload.Write([]byte{message.State, message.Severity})
	tdsU16(&payload, uint16(len(text)/2))
	payload.Write(text)
	payload.WriteByte(byte(len(server) / 2))
	payload.Write(server)
	payload.WriteByte(byte(len(procedure) / 2))
	payload.Write(procedure)
	tdsU32(&payload, message.Line)
	var token bytes.Buffer
	tdsToken(&token, kind, payload.Bytes())
	return token.Bytes(), nil
}

// Generic errors retain the historical byte bound and wire defaults. Bound
// before repairing invalid UTF-8 so an oversized error cannot amplify memory.
func tdsDefaultDiagnostic(number uint32, message string) Message {
	if len(message) > 2048 {
		message = message[:2048]
	}
	message = strings.ToValidUTF8(message, "\uFFFD")
	if len(message) > 2048 {
		message = message[:2048]
	}
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return Message{Number: number, State: 1, Severity: 16, Text: message, Server: "TDS", Line: 1}
}
