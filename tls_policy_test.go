/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tdsdriver "github.com/denisenkom/go-mssqldb"
)

func TestEncryptionNegotiation(t *testing.T) {
	for _, profile := range []struct {
		name                           string
		config                         transportConfig
		answers                        [4]byte
		encrypted, loginOnly, rejected [4]bool
	}{
		{"default plaintext", transportConfig{}, [4]byte{2, 2, 2, 2}, [4]bool{}, [4]bool{}, [4]bool{false, true, false, true}},
		{"default certificate", transportConfig{tls: &tls.Config{}}, [4]byte{3, 3, 3, 3}, [4]bool{true, true, false, true}, [4]bool{}, [4]bool{false, false, true, false}},
		{"optional", transportConfig{policy: EncryptionOptional, tls: &tls.Config{}}, [4]byte{0, 1, 2, 1}, [4]bool{true, true, false, true}, [4]bool{true, false, false, false}, [4]bool{}},
		{"required", transportConfig{policy: EncryptionRequired, tls: &tls.Config{}}, [4]byte{3, 1, 3, 1}, [4]bool{true, true, false, true}, [4]bool{}, [4]bool{false, false, true, false}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			for client := byte(0); client < 4; client++ {
				answer, encrypted, loginOnly, err := profile.config.negotiate(client)
				if answer != profile.answers[client] || encrypted != profile.encrypted[client] || loginOnly != profile.loginOnly[client] || (err != nil) != profile.rejected[client] {
					t.Fatalf("client %d: %d %v %v %v", client, answer, encrypted, loginOnly, err)
				}
			}
		})
	}
}

type unusedListener struct{ accepts int }

func (l *unusedListener) Accept() (net.Conn, error) { l.accepts++; return nil, net.ErrClosed }
func (*unusedListener) Close() error                { return nil }
func (*unusedListener) Addr() net.Addr              { return &net.TCPAddr{} }

func TestEncryptionConfigurationBeforeAccept(t *testing.T) {
	certificateCallback := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, fmt.Errorf("deferred fixture") }
	for _, invalid := range []Server{
		{EncryptionPolicy: EncryptionPolicy(255)},
		{EncryptionPolicy: EncryptionOptional},
		{EncryptionPolicy: EncryptionRequired},
		{TLSConfig: &tls.Config{}},
		{TLSConfig: &tls.Config{GetCertificate: certificateCallback, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12}},
		{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{}}}},
		{EncryptionPolicy: EncryptionOptional, TLSConfig: &tls.Config{GetCertificate: certificateCallback, MinVersion: tls.VersionTLS13}},
		{EncryptionPolicy: EncryptionOptional, TLSConfig: &tls.Config{GetCertificate: certificateCallback, MaxVersion: tls.VersionTLS11}},
		{EncryptionPolicy: EncryptionOptional, TLSConfig: &tls.Config{GetCertificate: certificateCallback, ClientAuth: tls.RequireAndVerifyClientCert}},
		{EncryptionPolicy: EncryptionOptional, TLSConfig: &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { panic("configuration callback must not run") }}},
	} {
		l := &unusedListener{}
		if invalid.ValidateConfig() == nil || invalid.Serve(l) == nil || l.accepts != 0 {
			t.Fatal("invalid configuration reached Accept", invalid.EncryptionPolicy, l.accepts)
		}
	}
	for _, policy := range []EncryptionPolicy{EncryptionDefault, EncryptionRequired} {
		config := &tls.Config{GetCertificate: certificateCallback, MinVersion: tls.VersionTLS13}
		s := Server{EncryptionPolicy: policy, TLSConfig: config}
		transport, err := s.transportConfig()
		if err != nil || transport.tls.MinVersion != tls.VersionTLS13 || transport.tls.MaxVersion != 0 || config.MaxVersion != 0 {
			t.Fatal("full TLS policy was capped or mutated", err)
		}
	}
	config := &tls.Config{GetCertificate: certificateCallback}
	s := Server{EncryptionPolicy: EncryptionOptional, TLSConfig: config}
	transport, err := s.transportConfig()
	if err != nil || loginOnlyTLSConfig(transport.tls).MaxVersion != tls.VersionTLS12 || config.MaxVersion != 0 || transport.tls.MaxVersion != 0 {
		t.Fatal("login-only version profile escaped its clone", err)
	}
}

func openPolicyClient(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	connector, err := tdsdriver.NewConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestReleasedClientOptionalEncryption(t *testing.T) {
	_, dsn, _ := startClient(t, true, func(s *Server) { s.EncryptionPolicy = EncryptionOptional })
	for _, encrypt := range []string{"false", "true", "disable"} {
		t.Run(encrypt, func(t *testing.T) {
			clientDSN := strings.Replace(dsn, "encrypt=true", "encrypt="+encrypt, 1)
			db := openPolicyClient(t, clientDSN)
			for i := 0; i < 2; i++ {
				var value int64
				if err := db.QueryRow("SELECT 1").Scan(&value); err != nil || value != 1 {
					t.Fatal(value, err)
				}
			}
		})
	}
	// A self-signed certificate is not trusted for full TLS. Login-only does
	// not authenticate the server certificate, matching the TDS client profile.
	for _, fixture := range []struct {
		encrypt  string
		rejected bool
	}{{"true", true}, {"false", false}} {
		db := openPolicyClient(t, strings.Replace(strings.Replace(dsn, "encrypt=true", "encrypt="+fixture.encrypt, 1), "TrustServerCertificate=true", "TrustServerCertificate=false", 1))
		var value int64
		err := db.QueryRow("SELECT 1").Scan(&value)
		if (err != nil) != fixture.rejected || err == nil && value != 1 {
			t.Fatal(fixture, value, err)
		}
	}
}

func TestReleasedClientRequiredRejectsUnsupported(t *testing.T) {
	_, dsn, _ := startClient(t, true, func(s *Server) { s.EncryptionPolicy = EncryptionRequired })
	for _, fixture := range []struct {
		encrypt  string
		rejected bool
	}{{"true", false}, {"false", false}, {"disable", true}} {
		db := openPolicyClient(t, strings.Replace(dsn, "encrypt=true", "encrypt="+fixture.encrypt, 1))
		var value int64
		err := db.QueryRow("SELECT 1").Scan(&value)
		if (err != nil) != fixture.rejected || err == nil && value != 1 {
			t.Fatal(fixture, value, err)
		}
	}
}

type captureWritesConn struct {
	net.Conn
	capture *bytes.Buffer
}

func (c *captureWritesConn) Write(p []byte) (int, error) {
	if c.capture != nil {
		return c.capture.Write(p)
	}
	return c.Conn.Write(p)
}

func policyDial(t *testing.T, dsn string, encryption byte) net.Conn {
	t.Helper()
	values := map[string]string{}
	for _, part := range strings.Split(dsn, ";") {
		if k, v, ok := strings.Cut(part, "="); ok {
			values[k] = v
		}
	}
	c, err := net.Dial("tcp", net.JoinHostPort(values["server"], values["port"]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// VERSION precedes ENCRYPTION, as required by MS-TDS PRELOGIN.
	if err := writeTDSMessage(c, 0x12, []byte{0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 255, 16, 0, 0, 1, 0, 0, encryption}); err != nil {
		t.Fatal(err)
	}
	m, err := readTDSMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := tdsPreloginEncryption(m.data)
	if err != nil || answer != encryption {
		t.Fatal(answer, err)
	}
	return c
}

func policyLogin() []byte {
	data := make([]byte, 94)
	binary.LittleEndian.PutUint32(data[4:], 0x74000004)
	for _, field := range []struct {
		offset   int
		text     string
		password bool
	}{{40, "alice", false}, {44, "secret", true}, {68, "fixture", false}} {
		value := tdsUTF16(field.text)
		if field.password {
			for i, b := range value {
				value[i] = (b<<4 | b>>4) ^ 0xa5
			}
		}
		binary.LittleEndian.PutUint16(data[field.offset:], uint16(len(data)))
		binary.LittleEndian.PutUint16(data[field.offset+2:], uint16(len(value)/2))
		data = append(data, value...)
	}
	binary.LittleEndian.PutUint32(data, uint32(len(data)))
	return data
}

func policyPacket(kind, status, id byte, payload []byte) []byte {
	frame := make([]byte, 8, len(payload)+8)
	frame[0], frame[1], frame[6] = kind, status, id
	binary.BigEndian.PutUint16(frame[2:], uint16(len(payload)+8))
	return append(frame, payload...)
}

func TestLoginOnlyPacketBoundary(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		for _, splitRecord := range []bool{false, true} {
			t.Run(fmt.Sprintf("fragmented=%v/splitRecord=%v", fragmented, splitRecord), func(t *testing.T) {
				_, dsn, _ := startClient(t, true, func(s *Server) { s.EncryptionPolicy = EncryptionOptional })
				raw := policyDial(t, dsn, 0)
				capture := &captureWritesConn{Conn: raw}
				wrapper := &tdsTLSHandshakeConn{Conn: capture}
				encrypted := tls.Client(wrapper, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
				if err := encrypted.Handshake(); err != nil {
					t.Fatal(err)
				}
				wrapper.raw = true
				var ciphertext bytes.Buffer
				capture.capture = &ciphertext
				login := policyLogin()
				first, rest := login, []byte(nil)
				status := byte(1)
				if fragmented {
					first, rest, status = login[:64], login[64:], 0
				}
				packet := policyPacket(0x10, status, 1, first)
				if splitRecord {
					if _, err := encrypted.Write(packet[:3]); err != nil {
						t.Fatal(err)
					}
					packet = packet[3:]
				}
				if _, err := encrypted.Write(packet); err != nil {
					t.Fatal(err)
				}
				wire := append([]byte(nil), ciphertext.Bytes()...)
				if fragmented {
					wire = append(wire, policyPacket(0x10, 1, 2, rest)...)
				}
				// Coalesce the plaintext continuation and first SQL request with
				// the encrypted first packet; no TLS read-ahead may swallow them.
				var query bytes.Buffer
				if err := writeTDSMessage(&query, 3, encodeRPC(10, textParam("SELECT 1"))); err != nil {
					t.Fatal(err)
				}
				wire = append(wire, query.Bytes()...)
				if _, err := raw.Write(wire); err != nil {
					t.Fatal(err)
				}
				ack, err := readTDSMessage(raw)
				if err != nil || !bytes.Contains(ack.data, []byte{0xad}) {
					t.Fatal("plaintext login acknowledgement", err)
				}
				result, err := readTDSMessage(raw)
				if err != nil || !bytes.Contains(result.data, rowIntPattern(1, false)) {
					t.Fatal("coalesced request", fmt.Sprintf("%x", result.data), err)
				}
				if result := exchange(t, raw, 10, textParam("SELECT 1")); !bytes.Contains(result, rowIntPattern(1, false)) {
					t.Fatal("subsequent plaintext request")
				}
			})
		}
	}
}

func TestLoginOnlyRejectsEncryptedExtraBeforeAuthentication(t *testing.T) {
	var authenticated atomic.Int64
	_, dsn, _ := startClient(t, true, func(s *Server) {
		s.EncryptionPolicy = EncryptionOptional
		auth := s.Handler.Authenticate
		s.Handler.Authenticate = func(ctx context.Context, l Login) (Session, error) { authenticated.Add(1); return auth(ctx, l) }
	})
	raw := policyDial(t, dsn, 0)
	wrapper := &tdsTLSHandshakeConn{Conn: raw}
	encrypted := tls.Client(wrapper, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if err := encrypted.Handshake(); err != nil {
		t.Fatal(err)
	}
	wrapper.raw = true
	packet := append(policyPacket(0x10, 1, 1, policyLogin()), 0)
	if _, err := encrypted.Write(packet); err != nil {
		t.Fatal(err)
	}
	_, err := readTDSMessage(raw)
	if err == nil || authenticated.Load() != 0 {
		t.Fatal("extra encrypted bytes reached authentication", err, authenticated.Load())
	}
}

func TestTLSRecordReaderDoesNotReadPlaintextAhead(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	record := []byte{23, 3, 3, 0, 3, 1, 2, 3}
	plain := []byte("plain")
	done := make(chan error, 1)
	go func() { _, err := right.Write(append(record, plain...)); done <- err }()
	reader := &tlsRecordConn{Conn: left}
	buf := make([]byte, 100)
	n, err := reader.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], record[:5]) {
		t.Fatal(n, err)
	}
	n, err = reader.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], record[5:]) {
		t.Fatal(n, err)
	}
	if _, err := io.ReadFull(left, buf[:len(plain)]); err != nil || !bytes.Equal(buf[:len(plain)], plain) {
		t.Fatal("read-ahead consumed plaintext", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
