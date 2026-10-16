// quic-nlb-demo: a minimal quic-go server that satisfies AWS NLB QUIC passthrough
// requirements from the AWS Load Balancer Controller QUIC guide and the
// draft-ietf-quic-load-balancers spec.
//
// - Reads the LBC-injected AWS_LBC_QUIC_SERVER_ID (base64) into an 8-byte ID
// - Emits 17-byte DCIDs: 1 config byte + 8-byte Server ID + N-byte nonce
//   (nonce length is 8 by default; can be set to 7 to reproduce the Envoy
//   worker-ID layout for the failure demo)
// - TLS 1.3, optionally requires+verifies client certs signed by a fleet CA
//
// Env vars:
//   AWS_LBC_QUIC_SERVER_ID  (required) base64-encoded 8-byte server id
//   QUIC_NONCE_LEN          (default 8) 7 or 8; 7 triggers 16-byte CID failure
//   MTLS_ENABLED            (default false) "true" to require client certs
//   TLS_CERT_FILE           (default /etc/quic/tls.crt)
//   TLS_KEY_FILE            (default /etc/quic/tls.key)
//   CLIENT_CA_FILE          (default /etc/quic/ca.crt) required when MTLS_ENABLED=true
//   LISTEN_ADDR             (default :3000)
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	serverIDLen = 8
	cidTotal    = 17
)

// serverIDCIDGenerator produces plaintext QUIC-LB Connection IDs of length 17:
//
//	byte 0     : config rotation (top 3 bits) + optional length (low 5 bits)
//	bytes 1..8 : 8-byte Server ID
//	bytes 9..N : nonce (8 bytes normally; 7 to reproduce Envoy layout)
type serverIDCIDGenerator struct {
	serverID []byte // 8 bytes
	nonceLen int    // 7 or 8
}

func (g *serverIDCIDGenerator) ConnectionIDLen() int {
	return 1 + serverIDLen + g.nonceLen
}

func (g *serverIDCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	out := make([]byte, g.ConnectionIDLen())
	// config rotation = 0, no self-encoded length
	out[0] = 0x00
	copy(out[1:1+serverIDLen], g.serverID)
	if _, err := io.ReadFull(rand.Reader, out[1+serverIDLen:]); err != nil {
		return quic.ConnectionID{}, err
	}
	return quic.ConnectionIDFromBytes(out), nil
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadServerID() ([]byte, error) {
	raw := os.Getenv("AWS_LBC_QUIC_SERVER_ID")
	if raw == "" {
		return nil, errors.New("AWS_LBC_QUIC_SERVER_ID not set (namespace label + pod annotation required)")
	}
	// Per the LBC QUIC guide, the server ID is base64-encoded.
	sid, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("base64 decode server id: %w", err)
	}
	if len(sid) != serverIDLen {
		return nil, fmt.Errorf("server id must decode to %d bytes, got %d", serverIDLen, len(sid))
	}
	return sid, nil
}

func buildTLSConfig() (*tls.Config, error) {
	certFile := envDefault("TLS_CERT_FILE", "/etc/quic/tls.crt")
	keyFile := envDefault("TLS_KEY_FILE", "/etc/quic/tls.key")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // QUIC requires TLS 1.3 per RFC 9001
		NextProtos:   []string{"quic-echo"},
	}
	if os.Getenv("MTLS_ENABLED") == "true" {
		caFile := envDefault("CLIENT_CA_FILE", "/etc/quic/ca.crt")
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("no PEM data found in client CA file")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("mTLS: RequireAndVerifyClientCert against CA %s", caFile)
	} else {
		log.Printf("mTLS: disabled (server-only TLS baseline)")
	}
	return cfg, nil
}

func handleConn(conn *quic.Conn) {
	remote := conn.RemoteAddr()
	// Log verified client identity, if any (Comment 4 in blog: "show them how to check it")
	if state := conn.ConnectionState(); state.TLS.HandshakeComplete {
		for i, c := range state.TLS.PeerCertificates {
			log.Printf("peer cert[%d] subject=%q issuer=%q remote=%s",
				i, c.Subject.String(), c.Issuer.String(), remote)
		}
	}
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("accept stream: %v (remote=%s)", err, remote)
			return
		}
		go func(s *quic.Stream) {
			defer s.Close()
			buf := make([]byte, 4096)
			n, err := s.Read(buf)
			if err != nil && err != io.EOF {
				log.Printf("stream read: %v", err)
				return
			}
			resp := fmt.Sprintf("hello from %s @ %s\n", os.Getenv("HOSTNAME"), time.Now().Format(time.RFC3339))
			_, _ = s.Write([]byte(resp))
			log.Printf("echoed %d bytes to %s (received %d bytes from client)", len(resp), remote, n)
		}(str)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	sid, err := loadServerID()
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	nonceLen, err := strconv.Atoi(envDefault("QUIC_NONCE_LEN", "8"))
	if err != nil || (nonceLen != 7 && nonceLen != 8) {
		log.Fatalf("QUIC_NONCE_LEN must be 7 or 8, got %q", os.Getenv("QUIC_NONCE_LEN"))
	}

	gen := &serverIDCIDGenerator{serverID: sid, nonceLen: nonceLen}
	log.Printf("startup: server_id=%s server_id_len=%d nonce_len=%d connection_id_len=%d",
		hex.EncodeToString(sid), serverIDLen, nonceLen, gen.ConnectionIDLen())

	tlsConf, err := buildTLSConfig()
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	addr := envDefault("LISTEN_ADDR", ":3000")
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("resolve %s: %v", addr, err)
	}
	udpConn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		log.Fatalf("listen udp %s: %v", addr, err)
	}
	defer udpConn.Close()

	tr := &quic.Transport{
		Conn:                  udpConn,
		ConnectionIDGenerator: gen,
	}
	ln, err := tr.Listen(tlsConf, &quic.Config{})
	if err != nil {
		log.Fatalf("quic listen: %v", err)
	}
	log.Printf("listening on udp %s (mTLS=%s)", addr, envDefault("MTLS_ENABLED", "false"))

	// TCP shim on the same port so NLB TCP health checks pass. NLB uses TCP by
	// default for TCP_QUIC target groups; without a TCP listener the targets
	// stay unhealthy and never receive QUIC traffic.
	go func() {
		tcpLn, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("tcp health shim listen: %v", err)
		}
		log.Printf("tcp health shim listening on %s", addr)
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				log.Printf("tcp shim accept: %v", err)
				return
			}
			c.Close()
		}
	}()

	for {
		c, err := ln.Accept(context.Background())
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handleConn(c)
	}
}
