// Simple QUIC client for the mTLS-over-NLB demo. Connects to the NLB DNS
// name, presents a client certificate signed by the fleet CA, opens a stream,
// and prints the server response. Also prints the negotiated peer certificate
// (server) subject and TLS state — this is what a fleet device's own logs
// would show and is useful for the blog's Validation section.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	target := flag.String("target", "", "NLB DNS name:443 (e.g. quic-nlb-demo-abc.elb.us-west-2.amazonaws.com:443)")
	sni := flag.String("sni", "quic-example.local", "server_name to send in SNI (must match server cert)")
	caFile := flag.String("ca", "certs/ca.crt", "fleet CA to trust")
	certFile := flag.String("cert", "certs/client.crt", "client certificate")
	keyFile := flag.String("key", "certs/client.key", "client key")
	skipClientCert := flag.Bool("no-client-cert", false, "connect without presenting a client cert")
	flag.Parse()

	if *target == "" {
		log.Fatal("--target host:port is required")
	}

	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("no PEMs in %s", *caFile)
	}

	tlsConf := &tls.Config{
		RootCAs:    pool,
		ServerName: *sni,
		NextProtos: []string{"quic-echo"},
		MinVersion: tls.VersionTLS13,
	}
	if !*skipClientCert {
		crt, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("load client keypair: %v", err)
		}
		tlsConf.Certificates = []tls.Certificate{crt}
		log.Printf("client cert loaded: %s", *certFile)
	} else {
		log.Printf("connecting WITHOUT a client cert (should fail if mTLS enabled)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log.Printf("dialing quic://%s (sni=%s)", *target, *sni)
	conn, err := quic.DialAddr(ctx, *target, tlsConf, &quic.Config{})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "bye")

	state := conn.ConnectionState()
	log.Printf("connected. tls_version=0x%04x alpn=%s peer_certs=%d",
		state.TLS.Version, state.TLS.NegotiatedProtocol, len(state.TLS.PeerCertificates))
	for i, c := range state.TLS.PeerCertificates {
		log.Printf("server cert[%d] subject=%q issuer=%q", i, c.Subject.String(), c.Issuer.String())
	}
	// DCID inspection is done via tcpdump / packet capture in the blog's
	// Validation section; the quic-go API doesn't expose the DCID directly.

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	if _, err := str.Write([]byte("hello from client\n")); err != nil {
		log.Fatalf("write: %v", err)
	}
	str.Close()

	body, err := io.ReadAll(str)
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	fmt.Printf("server said: %s", body)
}
