/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type tdsTLSHandshakeConn struct {
	net.Conn
	buffer []byte
	raw    bool
}

func (c *tdsTLSHandshakeConn) Read(data []byte) (int, error) {
	if c.raw {
		return c.Conn.Read(data)
	}
	if len(c.buffer) == 0 {
		message, err := readTDSMessage(c.Conn)
		if err != nil {
			return 0, err
		}
		if message.kind != 0x12 {
			return 0, fmt.Errorf("expected TLS-in-TDS PRELOGIN packet")
		}
		c.buffer = message.data
	}
	n := copy(data, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}
func (c *tdsTLSHandshakeConn) Write(data []byte) (int, error) {
	if c.raw {
		return c.Conn.Write(data)
	}
	if err := writeTDSMessage(c.Conn, 0x12, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func tdsPreloginEncryption(data []byte) (byte, error) {
	encryption := byte(2)
	seen := make(map[byte]bool)
	for i := 0; i < len(data); i += 5 {
		if data[i] == 0xff {
			return encryption, nil
		}
		if len(data)-i < 5 {
			return 0, fmt.Errorf("truncated PRELOGIN options")
		}
		offset := int(binary.BigEndian.Uint16(data[i+1:]))
		length := int(binary.BigEndian.Uint16(data[i+3:]))
		if offset > len(data) || length > len(data)-offset || seen[data[i]] {
			return 0, fmt.Errorf("invalid PRELOGIN option bounds")
		}
		seen[data[i]] = true
		if data[i] == 1 {
			if length != 1 || data[offset] > 3 {
				return 0, fmt.Errorf("unsupported PRELOGIN encryption option")
			}
			encryption = data[offset]
		}
		if data[i] == 4 && (length != 1 || data[offset] != 0) {
			return 0, fmt.Errorf("MARS is unsupported")
		}
	}
	return 0, fmt.Errorf("unterminated PRELOGIN options")
}

type tdsLogin struct {
	user, password, database string
	browseMetadata           bool
	session                  Session
}

func decodeTDSLogin(data []byte) (tdsLogin, error) {
	var login tdsLogin
	if len(data) < 94 || int(binary.LittleEndian.Uint32(data)) != len(data) {
		return login, fmt.Errorf("invalid LOGIN7 length")
	}
	if binary.LittleEndian.Uint32(data[4:]) < 0x74000004 {
		return login, fmt.Errorf("TDS 7.4 or later client required")
	}
	if data[25]&0x80 != 0 || data[27]&1 != 0 {
		return login, fmt.Errorf("integrated authentication and password changes are not supported")
	}
	login.browseMetadata = data[25]&2 != 0 || data[26]&0x10 != 0
	get := func(pos int, password bool) (string, error) {
		offset := int(binary.LittleEndian.Uint16(data[pos:]))
		n := 2 * int(binary.LittleEndian.Uint16(data[pos+2:]))
		if offset > len(data) || n > len(data)-offset {
			return "", fmt.Errorf("invalid LOGIN7 field bounds")
		}
		field := data[offset : offset+n]
		if password {
			decoded := make([]byte, len(field))
			for i, ch := range field {
				ch ^= 0xa5
				decoded[i] = ch<<4 | ch>>4
			}
			field = decoded
		}
		return tdsText(field)
	}
	var err error
	if login.user, err = get(40, false); err != nil {
		return login, err
	}
	if login.password, err = get(44, true); err != nil {
		return login, err
	}
	if login.database, err = get(68, false); err != nil {
		return login, err
	}
	return login, nil
}

func (s *Server) handshake(ctx context.Context, conn net.Conn) (net.Conn, tdsLogin, error) {
	var login tdsLogin
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	message, err := readTDSMessage(conn)
	if err != nil {
		return conn, login, err
	}
	if message.kind != 0x12 {
		return conn, login, fmt.Errorf("expected PRELOGIN")
	}
	encryption, err := tdsPreloginEncryption(message.data)
	if err != nil {
		return conn, login, err
	}
	answer := byte(2) // ENCRYPT_NOT_SUP when no certificate was configured
	if s.TLSConfig != nil {
		answer = 3
	} // ENCRYPT_REQ: never downgrade a TLS listener
	response := []byte{0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 0xff, 16, 0, 0, 1, 0, 0, answer}
	if err := writeTDSMessage(conn, 4, response); err != nil {
		return conn, login, err
	}
	if s.TLSConfig != nil {
		if encryption == 2 {
			return conn, login, fmt.Errorf("this TDS listener requires encryption")
		}
		wrapper := &tdsTLSHandshakeConn{Conn: conn}
		encrypted := tls.Server(wrapper, s.TLSConfig)
		if err := encrypted.Handshake(); err != nil {
			return conn, login, err
		}
		wrapper.raw = true
		conn = encrypted
	} else if encryption == 1 || encryption == 3 {
		return conn, login, fmt.Errorf("TDS TLS certificate is not configured")
	}
	message, err = readTDSMessage(conn)
	if err != nil {
		return conn, login, err
	}
	if message.kind != 0x10 {
		return conn, login, fmt.Errorf("expected LOGIN7")
	}
	login, err = decodeTDSLogin(message.data)
	if err != nil {
		return conn, login, err
	}
	if login.database == "" {
		login.database = s.Database
	}
	session, authErr := s.Handler.Authenticate(ctx, Login{User: login.user, Password: login.password, Database: login.database, RemoteAddress: conn.RemoteAddr().String(), BrowseMetadata: login.browseMetadata})
	if authErr != nil {
		var tokens bytes.Buffer
		tdsError(&tokens, 18456, "Login failed")
		tdsDone(&tokens, 0xfd, 2, 0)
		_ = writeTDSMessage(conn, 4, tokens.Bytes())
		return conn, login, fmt.Errorf("TDS login denied")
	}
	login.session = session
	var tokens, ack bytes.Buffer
	ack.Write([]byte{1, 0x74, 0, 0, 4})
	tdsBText(&ack, s.product())
	ack.Write([]byte{16, 0, 0, 1})
	tdsToken(&tokens, 0xad, ack.Bytes())
	tdsDatabase(&tokens, login.database, "")
	var packetEnv bytes.Buffer
	packetEnv.WriteByte(4)
	tdsBText(&packetEnv, "4096")
	tdsBText(&packetEnv, "4096")
	tdsToken(&tokens, 0xe3, packetEnv.Bytes())
	tdsDone(&tokens, 0xfd, 0, 0)
	if err := writeTDSMessage(conn, 4, tokens.Bytes()); err != nil {
		if s.Handler.Close != nil {
			s.Handler.Close(session)
		}
		return conn, login, err
	}
	_ = conn.SetDeadline(time.Time{})
	login.password = ""
	return conn, login, nil
}
