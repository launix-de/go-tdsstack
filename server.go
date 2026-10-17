/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// Server can serve one or more listeners. Shutdown stops accepts and waits for
// active callbacks; Close cancels/terminates connections. Handlers are expected
// to honor request contexts. The protocol never starts runtime query goroutines.
type serverState struct {
	mu          sync.Mutex
	listeners   map[net.Listener]bool
	connections map[*connection]bool
	closed      bool
	wg          sync.WaitGroup
}

func (s *Server) product() string {
	if s.Product != "" {
		return s.Product
	}
	return "TDS"
}
func (s *Server) Serve(l net.Listener) error {
	if s.Handler.Authenticate == nil || s.Handler.Execute == nil {
		return fmt.Errorf("authentication and execution handlers are required")
	}
	s.state.mu.Lock()
	if s.state.closed {
		s.state.mu.Unlock()
		return net.ErrClosed
	}
	if s.state.listeners == nil {
		s.state.listeners = make(map[net.Listener]bool)
	}
	s.state.listeners[l] = true
	s.state.mu.Unlock()
	defer func() { s.state.mu.Lock(); delete(s.state.listeners, l); s.state.mu.Unlock() }()
	for {
		socket, err := l.Accept()
		if err != nil {
			return err
		}
		s.state.mu.Lock()
		if s.state.closed {
			s.state.mu.Unlock()
			socket.Close()
			return net.ErrClosed
		}
		connectionContext, cancelConnection := context.WithCancel(context.Background())
		c := &connection{conn: socket, server: s, ctx: connectionContext, cancelConnection: cancelConnection}
		if s.state.connections == nil {
			s.state.connections = make(map[*connection]bool)
		}
		s.state.connections[c] = true
		s.state.wg.Add(1)
		s.state.mu.Unlock()
		go c.serve()
	}
}
func (s *Server) Close() error {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	s.state.closed = true
	for l := range s.state.listeners {
		l.Close()
	}
	for c := range s.state.connections {
		c.cancelConnection()
		c.cancel()
		c.conn.Close()
	}
	return nil
}
func (s *Server) Shutdown(ctx context.Context) error {
	s.state.mu.Lock()
	s.state.closed = true
	for l := range s.state.listeners {
		l.Close()
	}
	s.state.mu.Unlock()
	// Wait only for callbacks: idle clients must not prevent graceful shutdown.
	done := make(chan struct{})
	go func() { s.state.wg.Wait(); close(done) }()
	s.state.mu.Lock()
	for c := range s.state.connections {
		if c.request.Load() == nil {
			c.cancelConnection()
			c.conn.Close()
		}
	}
	s.state.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.Close()
		return ctx.Err()
	}
}
func (s *Server) ActiveRequests() int {
	n := 0
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	for c := range s.state.connections {
		if c.request.Load() != nil {
			n++
		}
	}
	return n
}

type requestState struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	done, attention bool
}

func (r *requestState) attentionRequest() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return false
	}
	r.attention = true
	r.cancel()
	return true
}
func (r *requestState) finish() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	return r.attention
}

type prepared struct {
	text, declarations string
	bytes              int
}
type connection struct {
	ctx                       context.Context
	cancelConnection          context.CancelFunc
	conn                      net.Conn
	server                    *Server
	session                   Session
	database, initialDatabase string
	browseMetadata            bool
	request                   atomic.Pointer[requestState]
	transaction               uint64
	prepared                  map[int32]prepared
	preparedBytes             int
	nextPrepared              int32
	cursors                   map[int32]*cursorSnapshot
	cursorBytes               int
	nextCursor                int32
}

var nextTransaction atomic.Uint64

func (c *connection) cancel() {
	if r := c.request.Load(); r != nil {
		r.attentionRequest()
	}
}
func (c *connection) serve() {
	defer c.server.state.wg.Done()
	defer c.cancelConnection()
	defer c.conn.Close()
	defer func() { c.server.state.mu.Lock(); delete(c.server.state.connections, c); c.server.state.mu.Unlock() }()
	defer func() {
		if r := recover(); r != nil && c.server.ErrorLog != nil {
			c.server.ErrorLog(fmt.Errorf("connection: %v", r))
		}
	}()
	conn, login, err := c.server.handshake(c.ctx, c.conn)
	if err != nil {
		return
	}
	// Original socket remains the externally closed connection; encrypted conn is
	// used only by this connection owner and the reader goroutine.
	c.session = login.session
	c.database = login.database
	c.initialDatabase = login.database
	c.browseMetadata = login.browseMetadata
	defer func() {
		if c.server.Handler.Close != nil {
			c.server.Handler.Close(c.session)
		}
	}()
	messages := make(chan tdsMessage, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(messages)
		for {
			m, err := readTDSMessage(conn)
			if err != nil {
				c.cancelConnection()
				c.cancel()
				return
			}
			if m.kind == 6 {
				if r := c.request.Load(); r != nil && r.attentionRequest() {
					continue
				}
			}
			select {
			case messages <- m:
			case <-done:
				return
			}
		}
	}()
	for m := range messages {
		if c.execute(m, conn) != nil {
			return
		}
		c.server.state.mu.Lock()
		closed := c.server.state.closed
		c.server.state.mu.Unlock()
		if closed {
			return
		}
	}
}
func (c *connection) validateHeaders(data []byte) error {
	if _, err := tdsStripHeaders(data); err != nil {
		return err
	}
	end := int(binary.LittleEndian.Uint32(data))
	for offset := 4; offset < end; {
		if binary.LittleEndian.Uint16(data[offset+4:]) == 2 && binary.LittleEndian.Uint64(data[offset+6:]) != c.transaction {
			return fmt.Errorf("transaction descriptor does not match connection")
		}
		offset += int(binary.LittleEndian.Uint32(data[offset:]))
	}
	return nil
}
func (c *connection) completion(w *tdsResponse, x Completion) error {
	var b bytes.Buffer
	if x.Database != "" && x.Database != c.database {
		tdsDatabase(&b, x.Database, c.database)
		c.database = x.Database
	}
	switch x.Transaction {
	case TransactionStarted:
		if c.transaction != 0 {
			return fmt.Errorf("transaction already active")
		}
		c.transaction = nextTransaction.Add(1)
		tdsTransaction(&b, 8, c.transaction)
	case TransactionCommitted, TransactionRolledBack:
		if c.transaction != 0 {
			kind := byte(9)
			if x.Transaction == TransactionRolledBack {
				kind = 10
			}
			tdsTransaction(&b, kind, c.transaction)
			c.transaction = 0
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}
func (c *connection) execute(m tdsMessage, conn net.Conn) (err error) {
	ctx, cancel := context.WithCancel(c.ctx)
	r := &requestState{ctx: ctx, cancel: cancel}
	c.request.Store(r)
	defer func() { r.finish(); cancel(); c.request.CompareAndSwap(r, nil) }()
	w := &tdsResponse{w: conn, kind: 4, id: 1, packetSize: tdsPacketSize}
	rpc := m.kind == 3
	var handle int32
	var handleName string
	published := false
	defer func() {
		if handle != 0 && !published {
			c.removePrepared(handle)
		}
	}()
	defer func() {
		if failure := recover(); failure != nil {
			if cause, ok := failure.(error); ok {
				err = fmt.Errorf("request: %w", cause)
			} else {
				err = fmt.Errorf("request: %v", failure)
			}
		}
		if err != nil {
			var b bytes.Buffer
			if r.finish() {
				tdsDone(&b, 0xfd, 0x20, 0)
			} else {
				var diagnostic Diagnostic
				var applicationError *DiagnosticError
				if errors.As(err, &applicationError) && applicationError != nil {
					diagnostic = applicationError.Diagnostic
				} else {
					diagnostic = tdsDefaultDiagnostic(50000, err.Error())
				}
				token, encodingError := tdsDiagnostic(0xaa, diagnostic)
				if encodingError != nil {
					// No bytes have been published. Reject the payload through the
					// same error completion using a known bounded diagnostic.
					token, _ = tdsDiagnostic(0xaa, tdsDefaultDiagnostic(50000, encodingError.Error()))
				}
				b.Write(token)
				if rpc {
					b.WriteByte(0x79)
					tdsU32(&b, 1)
					tdsDone(&b, 0xfe, 2, 0)
				} else {
					tdsDone(&b, 0xfd, 2, 0)
				}
			}
			if e := tdsWriteAll(w, b.Bytes()); e != nil {
				err = e
				return
			}
			err = w.flush(true)
		}
	}()
	if m.status&0x10 != 0 {
		return fmt.Errorf("RESETCONNECTIONSKIPTRAN unsupported")
	}
	if m.status&8 != 0 {
		if c.server.Handler.Reset == nil {
			return fmt.Errorf("reset handler unavailable")
		}
		session, e := c.server.Handler.Reset(ctx, c.session)
		if e != nil {
			return e
		}
		c.session = session
		c.prepared = nil
		c.preparedBytes = 0
		c.cursors = nil
		c.cursorBytes = 0
		c.transaction = 0
		var b bytes.Buffer
		tdsDatabase(&b, c.initialDatabase, c.database)
		c.database = c.initialDatabase
		tdsToken(&b, 0xe3, []byte{18, 0, 0})
		if e = tdsWriteAll(w, b.Bytes()); e != nil {
			return e
		}
	}
	if c.server.Handler.BeginRequest != nil {
		if err = c.server.Handler.BeginRequest(ctx, c.session); err != nil {
			return err
		}
	}
	writer := &resultWriter{w: w, ctx: ctx, rpc: rpc, completion: func(x Completion) error { return c.completion(w, x) }, active: func() bool { return c.transaction != 0 }}
	if m.kind == 6 {
		var b bytes.Buffer
		tdsDone(&b, 0xfd, 0x20, 0)
		if err = tdsWriteAll(w, b.Bytes()); err != nil {
			return err
		}
		return w.flush(true)
	}
	if err = c.validateHeaders(m.data); err != nil {
		return err
	}
	request := Request{Database: c.database, BrowseMetadata: c.browseMetadata}
	execute := true
	switch m.kind {
	case 1:
		data, e := tdsStripHeaders(m.data)
		if e != nil {
			return e
		}
		request.Text, e = tdsText(data)
		if e != nil {
			return e
		}
	case 3:
		decoded, e := decodeTDSRPC(m.data)
		if e != nil {
			return e
		}
		if decoded.metadata != "" {
			if c.server.Handler.Metadata == nil {
				return fmt.Errorf("metadata handler unavailable")
			}
			request.Procedure = decoded.metadata
			request.Parameters = rpcParameters(decoded, 0)
			err = c.server.Handler.Metadata(ctx, c.session, request, writer)
			execute = false
		} else if decoded.procedure == 2 || decoded.procedure == 7 || decoded.procedure == 8 || decoded.procedure == 9 {
			return c.cursorRPC(decoded, r, w)
		} else {
			request, handle, handleName, execute, err = c.prepareRPC(ctx, decoded, writer)
		}
		if err != nil {
			return err
		}
	case 14:
		transaction, e := decodeTransaction(m.data)
		if e != nil {
			return e
		}
		if c.server.Handler.Transaction == nil {
			return fmt.Errorf("transaction handler unavailable")
		}
		successor := transaction.Successor
		successorIsolation := transaction.SuccessorIsolation
		transaction.Successor = false
		transaction.SuccessorIsolation = 0
		completion, e := c.server.Handler.Transaction(ctx, c.session, transaction)
		if e != nil {
			return e
		}
		completion.More = successor
		if err = writer.Done(completion); err != nil {
			return err
		}
		if successor {
			// Complete the old transaction before asking for its successor.
			// A failed completion never invokes the second callback.
			next, e := c.server.Handler.Transaction(ctx, c.session, TransactionRequest{Action: Begin, Isolation: successorIsolation})
			if e != nil {
				return e
			}
			writer.done = false
			if err = writer.Done(next); err != nil {
				return err
			}
		}
		execute = false
	default:
		return fmt.Errorf("unsupported packet type %02x", m.kind)
	}
	if execute {
		if err = c.server.Handler.Execute(ctx, c.session, request, writer); err != nil {
			return err
		}
	}
	if writer.err != nil {
		return writer.err
	}
	if !writer.done {
		if err = writer.Done(Completion{Rows: writer.count}); err != nil {
			return err
		}
	}
	var b bytes.Buffer
	if r.finish() {
		tdsDone(&b, 0xfd, 0x20, 0)
	} else if rpc {
		b.WriteByte(0x79)
		tdsU32(&b, 0)
		if handle != 0 {
			tdsReturnHandle(&b, handleName, handle)
		}
		tdsDone(&b, 0xfe, 0, 0)
	}
	if err = tdsWriteAll(w, b.Bytes()); err != nil {
		return err
	}
	err = w.flush(true)
	if err == nil && ctx.Err() == nil {
		published = true
	}
	return err
}
func decodeTransaction(data []byte) (TransactionRequest, error) {
	var t TransactionRequest
	data, err := tdsStripHeaders(data)
	if err != nil {
		return t, err
	}
	d := tdsDecoder{data: data}
	kind := d.u16()
	switch kind {
	case 5:
		t.Action = Begin
		t.Isolation = d.u8()
		if len(d.take(int(d.u8()))) != 0 {
			return t, fmt.Errorf("named transaction unsupported")
		}
	case 7, 8:
		t.Action = Commit
		if kind == 8 {
			t.Action = Rollback
		}
		if len(d.take(int(d.u8()))) != 0 {
			return t, fmt.Errorf("named transaction unsupported")
		}
		flags := d.u8()
		if flags&^byte(1) != 0 {
			return t, fmt.Errorf("invalid transaction flags")
		}
		if flags&1 != 0 {
			t.Successor = true
			t.SuccessorIsolation = d.u8()
			if len(d.take(int(d.u8()))) != 0 {
				return t, fmt.Errorf("named successor unsupported")
			}
		}
	default:
		return t, fmt.Errorf("unsupported transaction action")
	}
	if t.Isolation != 0 && t.Isolation != 2 && t.Isolation != 5 || t.SuccessorIsolation != 0 && t.SuccessorIsolation != 2 && t.SuccessorIsolation != 5 {
		return t, fmt.Errorf("unsupported transaction isolation")
	}
	if d.err != nil {
		return t, d.err
	}
	if len(d.data) != 0 {
		return t, fmt.Errorf("trailing transaction data")
	}
	return t, nil
}
