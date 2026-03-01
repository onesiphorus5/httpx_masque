// Package spec – built-in target servers for data-plane conformance tests.
//
// StartH2CTarget starts an HTTP/2 cleartext (h2c) server used as the target
// for TCP CONNECT tunnels (RFC 9113 §8.5, RFC 9114 §4.4).
//
// StartHTTP3Target starts an HTTP/3 (QUIC) server used as the target for
// CONNECT-UDP / MASQUE tunnels (RFC 9298).
package spec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/quic-go/quic-go/http3"
)

// StartH2CTarget starts an h2c (HTTP/2 cleartext) server on host:port.
// GET / responds 200 OK with body "ok".  port=0 auto-assigns.
func StartH2CTarget(host string, port int) (addr string, stop func(), err error) {
	listenAddr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", nil, fmt.Errorf("listen TCP %s: %w", listenAddr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})

	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	go srv.Serve(ln) //nolint:errcheck

	return ln.Addr().String(), func() { srv.Close() }, nil
}

// StartHTTP3Target starts an HTTP/3 (QUIC) server on host:port using an
// ephemeral self-signed TLS certificate.  GET / responds 200 OK with body
// "ok".  port=0 auto-assigns.
func StartHTTP3Target(host string, port int) (addr string, stop func(), err error) {
	listenAddr := fmt.Sprintf("%s:%d", host, port)
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return "", nil, fmt.Errorf("listen UDP %s: %w", listenAddr, err)
	}

	tlsCfg, err := generateSelfSignedTLSForH3()
	if err != nil {
		pc.Close() //nolint:errcheck
		return "", nil, fmt.Errorf("generate TLS cert: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})

	srv := &http3.Server{Handler: mux, TLSConfig: tlsCfg}
	go srv.Serve(pc) //nolint:errcheck

	return pc.LocalAddr().String(), func() { srv.Close() }, nil //nolint:errcheck
}

// generateSelfSignedTLSForH3 creates an ephemeral ECDSA P-256 self-signed
// TLS certificate for the HTTP/3 target server.  The http3.Server.Serve
// will override NextProtos to "h3", so we only need the certificate here.
func generateSelfSignedTLSForH3() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "h3-target"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
