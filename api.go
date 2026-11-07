/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"context"
	"crypto/tls"
)

// WireType is an explicit protocol descriptor. Size is bytes; Scale and Precision
// are transmitted unchanged. SQL declarations and implicit conversions belong to
// the application, including for NULL values.
type WireType struct {
	Kind             byte
	Size             int
	Scale, Precision byte
	Collation        [5]byte
}

// Parameter owns its decoded data. Value is nil, int64, float64, bool, string,
// []byte, Decimal, Temporal, or Variant; it is never an application/runtime value.
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

// Variant carries one non-NULL scalar and its explicit base descriptor. Use the
// same descriptors as ordinary values (for example INTN with Size 4 for INT).
// Its enclosing column/parameter uses Kind 0x62 and Size at most 8016. A SQL
// NULL is represented by nil, never by a Variant whose Value is nil.
// Nested variants, MAX/LOB, GUID and unrecognized base types are unsupported.
type Variant struct {
	Type  WireType
	Value any
}

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
type Completion struct {
	Rows          uint64
	CountRows     bool // Use the number of rows emitted in this result set.
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

// Message is a TDS informational token payload selected by the application.
// The transport does not assign SQL meaning to its number, state or severity.
type Message struct {
	Number                  uint32
	State, Severity         byte
	Text, Server, Procedure string
	Line                    uint32
}

// ResultWriter permits sequential result sets and serializes parallel row
// callbacks. Fields must precede rows; Done ends one result. Methods return wire
// errors and never synthesize descriptors or perform SQL conversion.
type ResultWriter interface {
	Info(Message) error
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
	// State snapshots transport state after a failed Execute, before ERROR/DONE.
	State func(context.Context, Session) (Completion, error)
	Reset func(context.Context, Session) (Session, error)
	Close func(Session)
}
type Server struct {
	// Collation is an application-selected session default announced at login.
	// The all-zero value preserves the legacy behavior of no announcement.
	Collation [5]byte
	Handler   Handler
	Database  string
	TLSConfig *tls.Config
	Product   string
	ErrorLog  func(error)
	state     serverState
}
