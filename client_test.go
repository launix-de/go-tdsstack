/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"github.com/golang-sql/sqlexp"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tdsdriver "github.com/denisenkom/go-mssqldb"
)

func fixtureColumn(name string, kind byte, size int) Column {
	return Column{Name: name, WireType: WireType{Kind: kind, Size: size, Collation: [5]byte{9, 4, 0xd0, 0, 52}}, Flags: 1}
}
func startClient(t *testing.T, encrypted bool, configure ...func(*Server)) (*sql.DB, string, *Server) {
	t.Helper()
	s := &Server{Database: "fixture"}
	s.Handler.Authenticate = func(_ context.Context, login Login) (Session, error) {
		if login.User != "alice" || login.Password != "secret" || login.Database != "fixture" {
			return nil, fmt.Errorf("denied")
		}
		return new(int), nil
	}
	s.Handler.Reset = func(_ context.Context, _ Session) (Session, error) { return new(int), nil }
	s.Handler.Describe = func(_ context.Context, _ Session, r Request) ([]Column, error) {
		if r.Text == "SELECT forbidden" {
			return nil, fmt.Errorf("unsupported fixture")
		}
		return []Column{fixtureColumn("v", 0x26, 8)}, nil
	}
	s.Handler.Execute = func(ctx context.Context, _ Session, r Request, w ResultWriter) error {
		switch r.Text {
		case "SELECT batches":
			for _, c := range []Completion{{Rows: 2, More: true}, {Rows: 3, More: true}} {
				if err := w.Done(c); err != nil {
					return err
				}
			}
			if err := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); err != nil {
				return err
			}
			if err := w.Row([]any{int64(33)}); err != nil {
				return err
			}
			return w.Done(Completion{Rows: 1})
		case "SELECT 1":
			if err := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); err != nil {
				return err
			}
			return w.Row([]any{int64(1)})
		case "SELECT types":
			columns := []Column{fixtureColumn("i", 0x26, 8), fixtureColumn("f", 0x6d, 8), fixtureColumn("b", 0x68, 1), fixtureColumn("s", 0xe7, 65535), fixtureColumn("n", 0x26, 8)}
			if e := w.Fields(columns); e != nil {
				return e
			}
			return w.Row([]any{int64(9007199254740993), float64(2.5), true, "Grüße 🐘", nil})
		case "SELECT parameter":
			if len(r.Parameters) != 1 {
				return fmt.Errorf("missing native parameter")
			}
			if e := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); e != nil {
				return e
			}
			return w.Row([]any{r.Parameters[0].Value})
		case "SELECT fractional":
			col := Column{Name: "v", WireType: WireType{Kind: 0x2a, Scale: 7}, Flags: 1}
			if e := w.Fields([]Column{col}); e != nil {
				return e
			}
			return w.Row([]any{Temporal{738944, 495301234567, 0}})
		case "SELECT exact":
			col := Column{Name: "v", WireType: WireType{Kind: 0x6a, Size: 17, Precision: 38, Scale: 10}, Flags: 1}
			if e := w.Fields([]Column{col}); e != nil {
				return e
			}
			return w.Row([]any{Decimal{"12345678901234567890123456781234567890"}})
		case "SELECT many":
			if e := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); e != nil {
				return e
			}
			for i := int64(0); i < 400; i++ {
				if e := w.Row([]any{i}); e != nil {
					return e
				}
			}
			return nil
		case "SELECT empty":
			return w.Fields([]Column{fixtureColumn("v", 0x26, 8)})
		case "SELECT wait":
			<-ctx.Done()
			return ctx.Err()
		default:
			return fmt.Errorf("unknown opaque fixture text %q", r.Text)
		}
	}
	s.Handler.Transaction = func(_ context.Context, _ Session, r TransactionRequest) (Completion, error) {
		state := TransactionStarted
		if r.Action == Commit {
			state = TransactionCommitted
		}
		if r.Action == Rollback {
			state = TransactionRolledBack
		}
		return Completion{Transaction: state}, nil
	}
	if encrypted {
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	}
	for _, f := range configure {
		f(s)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { defer close(done); s.Serve(listener) }()
	t.Cleanup(func() { s.Close(); <-done })
	host, port, e := net.SplitHostPort(listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	dsn := fmt.Sprintf("server=%s;port=%s;user id=alice;password=secret;database=fixture;encrypt=disable;connection timeout=5", host, port)
	if encrypted {
		dsn = strings.Replace(dsn, "encrypt=disable", "encrypt=true;TrustServerCertificate=true", 1)
	}
	connector, e := tdsdriver.NewConnector(dsn)
	if e != nil {
		t.Fatal(e)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db, dsn, s
}
func TestReleasedClientConsecutiveCompletions(t *testing.T) {
	db, _, _ := startClient(t, false)
	var v int64
	if err := db.QueryRow("SELECT batches").Scan(&v); err != nil || v != 33 {
		t.Fatalf("result after consecutive metadata-free completions: %d, %v", v, err)
	}
}

func TestReleasedClientAuthTLSAndTypedResults(t *testing.T) {
	for _, tlsEnabled := range []bool{false, true} {
		t.Run(fmt.Sprint(tlsEnabled), func(t *testing.T) {
			db, dsn, _ := startClient(t, tlsEnabled)
			var v int
			if e := db.QueryRow("SELECT 1").Scan(&v); e != nil || v != 1 {
				t.Fatal(v, e)
			}
			var i int64
			var f float64
			var b bool
			var s string
			var n any
			if e := db.QueryRow("SELECT types").Scan(&i, &f, &b, &s, &n); e != nil || i != 9007199254740993 || f != 2.5 || !b || s != "Grüße 🐘" || n != nil {
				t.Fatal(i, f, b, s, n, e)
			}
			var decimal string
			if e := db.QueryRow("SELECT exact").Scan(&decimal); e != nil || decimal != "1234567890123456789012345678.1234567890" {
				t.Fatal(decimal, e)
			}
			var date time.Time
			if e := db.QueryRow("SELECT fractional").Scan(&date); e != nil || !date.Equal(time.Date(2024, 2, 29, 13, 45, 30, 123456700, time.UTC)) {
				t.Fatal(date, e)
			}
			rows, e := db.Query("SELECT empty")
			if e != nil {
				t.Fatal(e)
			}
			types, e := rows.ColumnTypes()
			if e != nil || len(types) != 1 || types[0].DatabaseTypeName() != "BIGINT" {
				t.Fatal(types, e)
			}
			if rows.Next() {
				t.Fatal("nonempty")
			}
			rows.Close()
			bad, e := tdsdriver.NewConnector(strings.Replace(dsn, "password=secret", "password=wrong", 1))
			if e != nil {
				t.Fatal(e)
			}
			denied := sql.OpenDB(bad)
			defer denied.Close()
			if denied.Ping() == nil {
				t.Fatal("wrong password accepted")
			}
		})
	}
}
func TestReleasedClientRPCAndPrepare(t *testing.T) {
	db, _, _ := startClient(t, false)
	var value int64
	if e := db.QueryRow("sp_executesql", sql.Named("stmt", "SELECT parameter"), sql.Named("params", "@v bigint"), sql.Named("v", int64(9007199254740993))).Scan(&value); e != nil || value != 9007199254740993 {
		t.Fatal(value, e)
	}
	// The raw prepare protocol is covered separately; the client's statement
	// wrapper may implement preparation locally and use exec-to-text RPCs.
	stmt, e := db.Prepare("SELECT parameter")
	if e != nil {
		t.Fatal(e)
	}
	defer stmt.Close()
	if e = stmt.QueryRow(sql.Named("v", int64(42))).Scan(&value); e != nil || value != 42 {
		t.Fatal(value, e)
	}
}
func TestReleasedClientAttentionThenReuse(t *testing.T) {
	db, _, s := startClient(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if e := db.QueryRowContext(ctx, "SELECT wait").Scan(new(int)); e == nil {
		t.Fatal("wait did not cancel")
	}
	var v int
	if e := db.QueryRow("SELECT 1").Scan(&v); e != nil || v != 1 {
		t.Fatal("connection reuse", v, e)
	}
	if s.ActiveRequests() != 0 {
		t.Fatal("request retained")
	}
}
func TestResultConcurrentRows(t *testing.T) {
	db, _, _ := startClient(t, false, func(s *Server) {
		execute := s.Handler.Execute
		s.Handler.Execute = func(ctx context.Context, session Session, r Request, w ResultWriter) error {
			if r.Text != "SELECT parallel" {
				return execute(ctx, session, r, w)
			}
			if e := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); e != nil {
				return e
			}
			var wg sync.WaitGroup
			errors := make(chan error, 4)
			for j := 0; j < 4; j++ {
				wg.Add(1)
				go func(j int) {
					defer wg.Done()
					for i := 0; i < 100; i++ {
						if e := w.Row([]any{int64(j*100 + i)}); e != nil {
							errors <- e
							return
						}
					}
				}(j)
			}
			wg.Wait()
			close(errors)
			for e := range errors {
				return e
			}
			return nil
		}
	})
	rows, e := db.Query("SELECT parallel")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	seen := map[int]bool{}
	for rows.Next() {
		var n int
		if e = rows.Scan(&n); e != nil {
			t.Fatal(e)
		}
		seen[n] = true
	}
	if rows.Err() != nil || len(seen) != 400 {
		t.Fatal(len(seen), rows.Err())
	}
}

func readInformationResults(t *testing.T, ctx context.Context, rows *sql.Rows, messages *sqlexp.ReturnMessage) ([]tdsdriver.Error, []int64) {
	t.Helper()
	var notices []tdsdriver.Error
	var values []int64
	active := true
	for active {
		switch message := messages.Message(ctx).(type) {
		case sqlexp.MsgNotice:
			notice, ok := message.Message.(tdsdriver.Error)
			if !ok {
				t.Fatalf("unexpected diagnostic carrier: %T", message.Message)
			}
			notices = append(notices, notice)
		case sqlexp.MsgError:
			t.Fatalf("information became an error: %v", message.Error)
		case sqlexp.MsgNext:
			for rows.Next() {
				var value int64
				if err := rows.Scan(&value); err != nil {
					t.Fatal(err)
				}
				values = append(values, value)
			}
		case sqlexp.MsgNextResultSet:
			active = rows.NextResultSet()
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
	}
	return notices, values
}

func TestClientInformationMessagesContinueAcrossResults(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint("encrypted=", encrypted), func(t *testing.T) {
			db, _, _ := startClient(t, encrypted, func(s *Server) {
				execute := s.Handler.Execute
				s.Handler.Execute = func(ctx context.Context, session Session, request Request, w ResultWriter) error {
					if request.Text != "opaque diagnostic sequence" {
						return execute(ctx, session, request, w)
					}
					for i, phase := range []string{"before", "between", "after"} {
						if err := w.Message(Diagnostic{Number: uint32(70001 + i), State: 7, Class: 9,
							Text: phase + " Grüße 🙂", Server: "node", Procedure: "load", Line: uint32(70000 + i)}); err != nil {
							return err
						}
						if i < 2 {
							if err := w.Fields([]Column{fixtureColumn("v", 0x26, 8)}); err != nil {
								return err
							}
							if err := w.Row([]any{int64(i + 1)}); err != nil {
								return err
							}
						}
						if err := w.Done(Completion{Rows: 1, More: i < 2, NoCount: i == 2}); err != nil {
							return err
						}
					}
					return nil
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			messages := &sqlexp.ReturnMessage{}
			rows, err := db.QueryContext(ctx, "opaque diagnostic sequence", messages)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			notices, values := readInformationResults(t, ctx, rows, messages)
			if rows.Err() != nil || !reflect.DeepEqual(values, []int64{1, 2}) || len(notices) != 3 {
				t.Fatal("result stream did not continue", rows.Err(), values, notices)
			}
			for i, notice := range notices {
				if notice.Number != int32(70001+i) || notice.State != 7 || notice.Class != 9 || notice.LineNo != int32(70000+i) ||
					notice.ServerName != "node" || notice.ProcName != "load" || notice.Message != []string{"before", "between", "after"}[i]+" Grüße 🙂" {
					t.Fatalf("client lost information fields: %#v", notice)
				}
			}
			var next int
			if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&next); err != nil || next != 1 {
				t.Fatal("information changed later request state", err, next)
			}
		})
	}
}

func TestClientInformationHonorsRequestCancellation(t *testing.T) {
	entered := make(chan struct{})
	observed := make(chan error, 1)
	db, _, _ := startClient(t, false, func(s *Server) {
		execute := s.Handler.Execute
		s.Handler.Execute = func(ctx context.Context, session Session, request Request, w ResultWriter) error {
			if request.Text != "opaque cancellable diagnostic" {
				return execute(ctx, session, request, w)
			}
			close(entered)
			<-ctx.Done()
			err := w.Message(Diagnostic{Text: "cancelled request must not publish this"})
			observed <- err
			return err
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := db.ExecContext(ctx, "opaque cancellable diagnostic")
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the application")
	}
	cancel()
	for _, result := range []<-chan error{finished, observed} {
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled owner was not respected", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation did not finish")
		}
	}
	var next int
	if err := db.QueryRow("SELECT 1").Scan(&next); err != nil || next != 1 {
		t.Fatal("cancelled information corrupted later requests", err, next)
	}
}

func TestClientPreparedRPCInformationNotices(t *testing.T) {
	var executions atomic.Int64
	db, _, _ := startClient(t, false, func(s *Server) {
		execute := s.Handler.Execute
		s.Handler.Execute = func(ctx context.Context, session Session, request Request, w ResultWriter) error {
			if request.Text == "SELECT parameter" {
				executions.Add(1)
				if err := w.Message(Diagnostic{Number: 70003, State: 8, Class: 3,
					Text: "prepared notice 🙂", Server: "node", Procedure: "load", Line: 70002}); err != nil {
					return err
				}
			}
			return execute(ctx, session, request, w)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var handle int64
	if _, err := conn.ExecContext(ctx, "sp_prepare", sql.Named("handle", sql.Out{Dest: &handle}),
		sql.Named("params", "@v bigint"), sql.Named("stmt", "SELECT parameter")); err != nil || handle <= 0 {
		t.Fatal("native prepare failed", err, handle)
	}
	if executions.Load() != 0 {
		t.Fatal("pure preparation invoked the execution callback")
	}
	check := func(rows *sql.Rows, messages *sqlexp.ReturnMessage, value int64) {
		notices, values := readInformationResults(t, ctx, rows, messages)
		err := rows.Err()
		rows.Close()
		if err != nil || !reflect.DeepEqual(values, []int64{value}) || len(notices) != 1 {
			t.Fatal("prepared information disrupted its result", err, values, notices)
		}
		notice := notices[0]
		if notice.Number != 70003 || notice.State != 8 || notice.Class != 3 || notice.LineNo != 70002 ||
			notice.Message != "prepared notice 🙂" || notice.ServerName != "node" || notice.ProcName != "load" {
			t.Fatalf("prepared RPC changed its information payload: %#v", notice)
		}
	}

	for i := int64(0); i < 2; i++ {
		messages := &sqlexp.ReturnMessage{}
		value := int64(9007199254740993) + i
		rows, err := conn.QueryContext(ctx, "sp_execute", sql.Named("handle", handle), sql.Named("v", value), messages)
		if err != nil {
			t.Fatal(err)
		}
		check(rows, messages, value)
	}
	var combined int64
	messages := &sqlexp.ReturnMessage{}
	rows, err := conn.QueryContext(ctx, "sp_prepexec", sql.Named("handle", sql.Out{Dest: &combined}),
		sql.Named("params", "@v bigint"), sql.Named("stmt", "SELECT parameter"), sql.Named("v", int64(42)), messages)
	if err != nil {
		t.Fatal("combined prepare/execute failed", err)
	}
	check(rows, messages, 42)
	if combined <= 0 || combined == handle {
		t.Fatal("information disrupted the prepared output handle", combined, handle)
	}
	for _, prepared := range []int64{handle, combined} {
		if _, err := conn.ExecContext(ctx, "sp_unprepare", sql.Named("handle", prepared)); err != nil {
			t.Fatal("prepared information changed handle lifecycle", err)
		}
	}
	if executions.Load() != 3 {
		t.Fatal("prepared request execution count", executions.Load())
	}
}

func TestClientStructuredErrorsPreserveDiagnostic(t *testing.T) {
	payload := Diagnostic{Number: 8115, State: 7, Class: 16, Text: "bounded failure Grüße 🙂", Server: "node", Procedure: "load", Line: 70001}
	db, _, _ := startClient(t, false, func(s *Server) {
		execute, describe := s.Handler.Execute, s.Handler.Describe
		s.Handler.Execute = func(ctx context.Context, session Session, r Request, w ResultWriter) error {
			switch r.Text {
			case "opaque structured failure":
				return fmt.Errorf("outer context: %w", fmt.Errorf("backend context: %w", &DiagnosticError{Diagnostic: payload}))
			case "opaque ordinary failure":
				return errors.New("ordinary backend failure")
			case "opaque nil diagnostic":
				var failure *DiagnosticError
				return fmt.Errorf("wrapped nil: %w", failure)
			case "opaque invalid diagnostic":
				return &DiagnosticError{Diagnostic: Diagnostic{Number: 8115, Procedure: strings.Repeat("🙂", 128)}}
			}
			return execute(ctx, session, r, w)
		}
		s.Handler.Describe = func(ctx context.Context, session Session, r Request) ([]Column, error) {
			if r.Text == "opaque describe failure" {
				return nil, fmt.Errorf("describe context: %w", &DiagnosticError{Diagnostic: payload})
			}
			return describe(ctx, session, r)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	check := func(err error, want Diagnostic) {
		t.Helper()
		var actual tdsdriver.Error
		if !errors.As(err, &actual) || uint32(actual.Number) != want.Number || actual.State != want.State || actual.Class != want.Class ||
			actual.Message != want.Text || actual.ServerName != want.Server || actual.ProcName != want.Procedure || uint32(actual.LineNo) != want.Line {
			t.Fatalf("client lost error diagnostic: %#v / %v; want %#v", actual, err, want)
		}
	}
	for _, method := range []string{"batch", "execute", "prepare", "prepexec", "prepared execute", "cursor"} {
		t.Run(method, func(t *testing.T) {
			var handle int64
			switch method {
			case "batch":
				_, err = conn.ExecContext(ctx, "opaque structured failure")
			case "execute":
				_, err = conn.ExecContext(ctx, "sp_executesql", sql.Named("stmt", "opaque structured failure"))
			case "prepare":
				_, err = conn.ExecContext(ctx, "sp_prepare", sql.Named("handle", sql.Out{Dest: &handle}), sql.Named("params", ""), sql.Named("stmt", "opaque describe failure"))
			case "prepexec":
				_, err = conn.ExecContext(ctx, "sp_prepexec", sql.Named("handle", sql.Out{Dest: &handle}), sql.Named("params", ""), sql.Named("stmt", "opaque structured failure"))
			case "prepared execute":
				var prepared int64
				if _, err := conn.ExecContext(ctx, "sp_prepare", sql.Named("handle", sql.Out{Dest: &prepared}), sql.Named("params", ""), sql.Named("stmt", "opaque structured failure")); err != nil || prepared <= 0 {
					t.Fatal("pure preparation failed", prepared, err)
				}
				_, err = conn.ExecContext(ctx, "sp_execute", sql.Named("handle", prepared))
				if _, cleanupError := conn.ExecContext(ctx, "sp_unprepare", sql.Named("handle", prepared)); cleanupError != nil {
					t.Fatal("failed execution invalidated the prepared handle", cleanupError)
				}
			case "cursor":
				var scroll, concurrency, count int64 = 8, 1, 0
				_, err = conn.ExecContext(ctx, "sp_cursoropen", sql.Named("cursor", sql.Out{Dest: &handle}), sql.Named("stmt", "opaque structured failure"),
					sql.Named("scroll", sql.Out{Dest: &scroll, In: true}), sql.Named("concurrency", sql.Out{Dest: &concurrency, In: true}), sql.Named("count", sql.Out{Dest: &count, In: true}))
			}
			check(err, payload)
			if handle != 0 {
				t.Fatal("failed request published a handle", handle)
			}
		})
	}
	_, err = conn.ExecContext(ctx, "opaque ordinary failure")
	check(err, Diagnostic{Number: 50000, State: 1, Class: 16, Text: "ordinary backend failure", Server: "TDS", Line: 1})
	_, err = conn.ExecContext(ctx, "opaque nil diagnostic")
	check(err, Diagnostic{Number: 50000, State: 1, Class: 16, Text: "wrapped nil: nil diagnostic error", Server: "TDS", Line: 1})
	_, err = conn.ExecContext(ctx, "opaque invalid diagnostic")
	check(err, Diagnostic{Number: 50000, State: 1, Class: 16, Text: "diagnostic fields exceed wire length limits", Server: "TDS", Line: 1})
	var value int
	if err := conn.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatal("error response corrupted the next request", value, err)
	}
}
