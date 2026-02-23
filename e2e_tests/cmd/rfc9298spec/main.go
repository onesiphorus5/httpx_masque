// rfc9298spec is an RFC 9298 (Proxying UDP in HTTP / MASQUE) conformance test
// runner, modelled after h2spec.
//
// Usage:
//
//	rfc9298spec [flags] [section...]
//
// Examples:
//
//	# Run all tests against a proxy on localhost:8443
//	rfc9298spec -host 127.0.0.1 -port 8443 -skip-verify
//
//	# Run only §3.4 tests
//	rfc9298spec -host 127.0.0.1 -port 8443 -skip-verify 3.4
//
//	# Run only test #2 in §3.4 (like h2spec)
//	rfc9298spec -host 127.0.0.1 -port 8443 -skip-verify 3.4/2
//
//	# Emit a JUnit report for CI
//	rfc9298spec -host 127.0.0.1 -port 8443 -skip-verify -junit-report report.xml
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"rfc9298spec/internal/config"
	"rfc9298spec/internal/reporter"
	"rfc9298spec/internal/spec"
	"rfc9298spec/sections/section3"
	"rfc9298spec/sections/section4"
	"rfc9298spec/sections/section5"
)

func main() {
	host := flag.String("host", "127.0.0.1", "proxy host")
	port := flag.Int("port", 8443, "proxy port")
	skipVerify := flag.Bool("skip-verify", false, "skip TLS certificate verification")
	timeout := flag.Duration("timeout", 5*time.Second, "per-test timeout")
	verbose := flag.Bool("verbose", false, "show extra failure detail")
	dryRun := flag.Bool("dry-run", false, "list tests without executing them")
	targetHost := flag.String("target-host", "127.0.0.1", "target host for UDP echo (auto-started)")
	targetPort := flag.Int("target-port", 0, "target port for UDP echo (0 = auto-assign)")
	pathTmpl := flag.String("path", "", `URI template path (default "/.well-known/masque/udp/{target_host}/{target_port}/"`)
	junitReport := flag.String("junit-report", "", "write JUnit XML report to this file")
	flag.Parse()

	// Section filter and optional case filter from positional arguments.
	// Syntax: "3.4"    – run all tests in section 3.4
	//         "3.4/2"  – run only test #2 in section 3.4 (like h2spec)
	var sectionFilter []string
	caseFilters := map[string]int{}
	for _, arg := range flag.Args() {
		if idx := strings.Index(arg, "/"); idx >= 0 {
			if n, err := strconv.Atoi(arg[idx+1:]); err == nil && n > 0 {
				section := arg[:idx]
				sectionFilter = append(sectionFilter, section)
				caseFilters[section] = n
				continue
			}
		}
		sectionFilter = append(sectionFilter, arg)
	}

	// Start the built-in UDP echo server so data-plane tests have a target.
	echoAddr, stopEcho, err := startUDPEchoServer(*targetHost, *targetPort)
	if err != nil {
		log.Fatalf("failed to start UDP echo server: %v", err)
	}
	defer stopEcho()

	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)
	fmt.Fprintf(os.Stderr, "UDP echo server listening on %s\n\n", echoAddr)

	cfg := &config.Config{
		Host:          *host,
		Port:          *port,
		TLSSkipVerify: *skipVerify,
		Timeout:       *timeout,
		Verbose:       *verbose,
		DryRun:        *dryRun,
		TargetHost:    echoHost,
		TargetPort:    echoPort,
		PathTemplate:  *pathTmpl,
		Sections:      sectionFilter,
		CaseFilters:   caseFilters,
	}

	groups := []*spec.TestGroup{
		section3.NewGroup(),
		section4.NewGroup(),
		section5.NewGroup(),
	}

	fmt.Printf("RFC 9298 – Proxying UDP in HTTP – Conformance Test Suite\n")
	fmt.Printf("  proxy  : %s\n", cfg.Addr())
	fmt.Printf("  target : %s\n\n", cfg.TargetAddr())

	r := reporter.New(os.Stdout)
	for _, g := range groups {
		if len(sectionFilter) > 0 && !cfg.ShouldRunSection(g.Section) {
			continue
		}
		g.Test(cfg, r)
	}

	r.PrintSummary(groups)

	if *junitReport != "" {
		if err := reporter.JUnitReport(*junitReport, groups); err != nil {
			log.Fatalf("write JUnit report: %v", err)
		}
		fmt.Fprintf(os.Stderr, "JUnit report written to %s\n", *junitReport)
	}

	_, failed, _ := spec.Totals(groups)
	if failed > 0 {
		os.Exit(1)
	}
}

// startUDPEchoServer starts a UDP server on host:port that echoes every
// datagram back to its sender.  port=0 auto-assigns.
func startUDPEchoServer(host string, port int) (addr string, stop func(), err error) {
	listenAddr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return "", nil, fmt.Errorf("listen UDP %s: %w", listenAddr, err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			conn.WriteTo(buf[:n], src) //nolint:errcheck
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }, nil
}
