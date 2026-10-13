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
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
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
