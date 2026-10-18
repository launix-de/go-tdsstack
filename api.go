/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"context"
	"crypto/tls"
)

// WireType is an explicit protocol descriptor. Size is bytes; Scale and Precision
// are transmitted unchanged. SQL declarations and implicit conversions belong to
// the application, including for NULL values. GUIDTYPE (0x24) uses Size 16
// and nil or exactly 16 payload bytes; the library preserves their wire order.
type WireType struct {
	Kind             byte
	Size             int
	Scale, Precision byte
	Collation        [5]byte
}

// Parameter owns its decoded data. Value is nil, int64, float64, bool, string,
// []byte, Decimal, or Temporal; it is never an application/runtime value.
type Parameter struct {
	Name  string
	Flags byte
	Type  WireType
	Value any
}

// Decimal carries the unscaled base-ten integer, without rounding or casts.
type Decimal struct{ Coefficient string }

// Temporal carries the protocol's day ordinal, clock units and offset minutes.
// The descriptor selects the epoch and clock scale; no calendar casts occur here.
type Temporal struct{ Days, Ticks, Offset int64 }

// Column flags/UserType are supplied by the application, not inferred from rows.
type Column struct {
	WireType
	Name     string
	Flags    uint16
	UserType uint32
	Source   [4]string
	Key      bool
	Browse   bool
}
type Login struct {
	User, Password, Database, RemoteAddress string
	BrowseMetadata                          bool
}

// Session is opaque application-owned connection state. The library never
// inspects it and does not persist sessions in prepared/cursor handles.
type Session = any

// Request retains opaque text and invocation-owned wire parameters. Declarations
// are parsed/bound only by the application. DescribeOnly must not execute SQL.
type Request struct {
	BrowseMetadata                          bool
	Database, Text, Declarations, Procedure string
	Parameters                              []Parameter
	Cursor                                  bool
}

// Diagnostic is an explicit INFO/ERROR-token payload. Text and name lengths use
// UTF-16 units; Line is the TDS 7.4 four-byte line field. No field is inferred,
// truncated, or normalized, and Class never promotes this payload to an error.
// ResultWriter.Message emits INFO; DiagnosticError returned by a handler emits
// ERROR. Applications select the token kind and all diagnostic metadata.
type Diagnostic struct {
	Number                  uint32
	State, Class            byte
	Text, Server, Procedure string
	Line                    uint32
}

// DiagnosticError returns application-supplied ERROR metadata through a handler's
// request error result. Wrapping with %w preserves the diagnostic; the wrapping
// text is not added to its wire Text. Invalid payloads fail with a bounded generic
// error instead of publishing malformed or truncated metadata.
type DiagnosticError struct {
	Diagnostic
}

func (e *DiagnosticError) Error() string {
	if e == nil {
		return "nil diagnostic error"
	}
	return e.Text
}

type Completion struct {
	Rows          uint64
	NoCount, More bool
	Database      string
	Transaction   TransactionState
}
type TransactionState byte

const (
	TransactionUnchanged TransactionState = iota
	TransactionStarted
	TransactionCommitted
	TransactionRolledBack
)

type TransactionAction byte

const (
	Begin TransactionAction = iota + 1
	Commit
	Rollback
)

type TransactionRequest struct {
	Action             TransactionAction
	Isolation          byte
	Successor          bool
	SuccessorIsolation byte
}

// ResultWriter permits sequential result sets and serializes parallel output
// callbacks. Fields must precede rows; Done ends one result. Methods return wire
// errors and never synthesize descriptors or perform SQL conversion.
type ResultWriter interface {
	// Message emits an INFO token without opening or completing a result. It
	// is valid before fields, between rows/results, and before final Done.
	Message(Diagnostic) error
	Fields([]Column) error
	Row([]any) error
	Done(Completion) error
}

// Handler callbacks own SQL/session semantics. Prepared text remains opaque to
// the library. Describe is pure; Transaction receives actions rather than SQL.
type Handler struct {
	Authenticate func(context.Context, Login) (Session, error)
	Execute      func(context.Context, Session, Request, ResultWriter) error
	Describe     func(context.Context, Session, Request) ([]Column, error)
	Metadata     func(context.Context, Session, Request, ResultWriter) error
	Transaction  func(context.Context, Session, TransactionRequest) (Completion, error)
	BeginRequest func(context.Context, Session) error
	Reset        func(context.Context, Session) (Session, error)
	Close        func(Session)
}
type Server struct {
	Handler   Handler
	Database  string
	TLSConfig *tls.Config
	Product   string
	ErrorLog  func(error)
	state     serverState
}
