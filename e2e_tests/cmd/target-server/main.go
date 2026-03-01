// target-server starts both an HTTPS/H2 and an HTTP/3 target server and
// blocks until SIGINT or SIGTERM.  It is intended to run inside a Docker
// container so that e2e test suites can reach a pre-started target over the
// network instead of spawning one locally.
//
// Usage:
//
//	target-server [flags]
//
// Flags:
//
//	-h2-host  host  HTTPS/H2 listen address (default "0.0.0.0")
//	-h2-port  port  HTTPS/H2 TCP listen port  (default 8444)
//	-h3-host  host  HTTP/3 listen address     (default "0.0.0.0")
//	-h3-port  port  HTTP/3 UDP listen port    (default 8445)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"rfc9298spec/internal/spec"
)

func main() {
	h2Host := flag.String("h2-host", "0.0.0.0", "HTTPS/H2 listen host")
	h2Port := flag.Int("h2-port", 8444, "HTTPS/H2 TCP listen port")
	h3Host := flag.String("h3-host", "0.0.0.0", "HTTP/3 UDP listen host")
	h3Port := flag.Int("h3-port", 8445, "HTTP/3 UDP listen port")
	flag.Parse()

	h2Addr, stopH2, err := spec.StartH2Target(*h2Host, *h2Port)
	if err != nil {
		log.Fatalf("start HTTPS/H2 target: %v", err)
	}
	defer stopH2()

	h3Addr, stopH3, err := spec.StartHTTP3Target(*h3Host, *h3Port)
	if err != nil {
		log.Fatalf("start HTTP/3 target: %v", err)
	}
	defer stopH3()

	fmt.Fprintf(os.Stderr, "HTTPS/H2 target listening on %s (TCP)\n", h2Addr)
	fmt.Fprintf(os.Stderr, "HTTP/3  target listening on %s (UDP)\n", h3Addr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "shutting down")
}
