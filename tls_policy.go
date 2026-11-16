/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type transportConfig struct {
	policy EncryptionPolicy
	tls    *tls.Config
}

// ValidateConfig checks transport configuration without opening or owning a
// listener. Serve repeats validation before its first Accept. Certificate
// callbacks remain deferred to the real ClientHello, as in crypto/tls.
func (s *Server) ValidateConfig() error {
	_, err := s.transportConfig()
	return err
}

func (s *Server) transportConfig() (transportConfig, error) {
	c := transportConfig{policy: s.EncryptionPolicy}
	if c.policy > EncryptionRequired {
		return c, fmt.Errorf("unknown TDS encryption policy")
	}
	if s.TLSConfig == nil {
		if c.policy != EncryptionDefault {
			return c, fmt.Errorf("TDS encryption policy requires TLSConfig")
		}
		return c, nil
	}
	c.tls = s.TLSConfig.Clone()
	if c.tls.MinVersion != 0 && c.tls.MaxVersion != 0 && c.tls.MinVersion > c.tls.MaxVersion {
		return c, fmt.Errorf("invalid TLS version range")
	}
	if len(c.tls.Certificates) == 0 && c.tls.GetCertificate == nil && c.tls.GetConfigForClient == nil {
		return c, fmt.Errorf("TLSConfig requires server credentials")
	}
	for _, certificate := range c.tls.Certificates {
		if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return c, fmt.Errorf("incomplete TLS server certificate")
		}
	}
	if c.policy == EncryptionOptional {
		if err := validateLoginOnlyTLS(c.tls); err != nil {
			return c, err
		}
	}
	return c, nil
}

func validateLoginOnlyTLS(c *tls.Config) error {
	// Optional accepts genuinely TLS-incapable clients. An operator-required
	// client certificate must therefore use the fully encrypted required policy.
	if c.ClientAuth != tls.NoClientCert {
		return fmt.Errorf("optional TDS encryption does not support client-certificate policy")
	}
	// A callback may replace the entire authentication policy. It cannot be
	// validated for TLS-incapable clients, which never send ClientHello. A
	// certificate-only GetCertificate callback does not have this ambiguity.
	if c.GetConfigForClient != nil {
		return fmt.Errorf("optional TDS encryption does not support GetConfigForClient; use GetCertificate")
	}
	// TDS 7.x login-only is a TLS 1.2 profile. Other full-TLS policies retain
	// their existing crypto/tls version behavior without an implicit cap.
	if c.MinVersion > tls.VersionTLS12 || c.MaxVersion != 0 && c.MaxVersion < tls.VersionTLS12 {
		return fmt.Errorf("optional TDS encryption requires TLS 1.2")
	}
	return nil
}

func loginOnlyTLSConfig(config *tls.Config) *tls.Config {
	c := config.Clone()
	c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	return c
}

func (c transportConfig) negotiate(client byte) (answer byte, encrypted, loginOnly bool, err error) {
	if c.tls == nil {
		if client == 1 || client == 3 {
			err = fmt.Errorf("TDS TLS certificate is not configured")
		}
		return 2, false, false, err
	}
	if c.policy == EncryptionOptional {
		switch client {
		case 0:
			return 0, true, true, nil
		case 2:
			return 2, false, false, nil
		default:
			return 1, true, false, nil
		}
	}
	answer = 3
	if c.policy == EncryptionRequired && (client == 1 || client == 3) {
		answer = 1
	}
	if client == 2 {
		return answer, false, false, fmt.Errorf("this TDS listener requires encryption")
	}
	return answer, true, false, nil
}

// crypto/tls deliberately reads ahead. Expose at most one TLS record at a
// time, including during the wrapped handshake, so plaintext following the
// first encrypted LOGIN7 packet never enters its private ciphertext buffer.
type tlsRecordConn struct {
	net.Conn
	header    [5]byte
	offset    int
	remaining int
	ready     bool
}

func (c *tlsRecordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.ready {
		if _, err := io.ReadFull(c.Conn, c.header[:]); err != nil {
			return 0, err
		}
		c.offset, c.remaining, c.ready = 0, int(binary.BigEndian.Uint16(c.header[3:])), true
	}
	if c.offset < len(c.header) {
		n := copy(p, c.header[c.offset:])
		c.offset += n
		if c.offset == len(c.header) && c.remaining == 0 {
			c.ready = false
		}
		return n, nil
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	if c.remaining == 0 {
		c.ready = false
	}
	return n, err
}

func readLoginOnlyMessage(encrypted *tls.Conn, transport *tdsTLSHandshakeConn) (tdsMessage, error) {
	// A read with this buffer drains an entire TLS 1.2 plaintext record. All
	// bytes are ours; tls.Conn cannot retain a hidden remainder at the switch.
	var record [65536]byte
	var first []byte
	frameSize := 0
	for frameSize == 0 || len(first) < frameSize {
		n, err := encrypted.Read(record[:])
		if err != nil {
			return tdsMessage{}, err
		}
		if n == 0 {
			return tdsMessage{}, io.ErrNoProgress
		}
		first = append(first, record[:n]...)
		if frameSize == 0 && len(first) >= 8 {
			header, size, err := readTDSPacketHeader(bytes.NewReader(first))
			if err != nil {
				return tdsMessage{}, err
			}
			if header[0] != 0x10 {
				return tdsMessage{}, fmt.Errorf("expected encrypted first LOGIN7 packet")
			}
			frameSize = 8 + size
		}
	}
	if len(first) != frameSize || len(transport.buffer) != 0 {
		return tdsMessage{}, fmt.Errorf("encrypted data exceeds first LOGIN7 packet")
	}
	// Neither Close nor a TLS shutdown alert belongs on the surviving socket.
	// The existing message owner validates plaintext continuation packets.
	return readTDSMessage(io.MultiReader(bytes.NewReader(first), transport.Conn))
}
