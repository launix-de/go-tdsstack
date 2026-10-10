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

// ResultWriter permits sequential result sets and serializes parallel row
// callbacks. Fields must precede rows; Done ends one result. Methods return wire
// errors and never synthesize descriptors or perform SQL conversion.
type ResultWriter interface {
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
