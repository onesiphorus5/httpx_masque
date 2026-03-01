// rfc9113spec is an RFC 9113 §8.5 (TCP tunnelling over HTTP/2) conformance
// test runner, modelled after h2spec.
//
// Usage:
//
//	rfc9113spec [flags] [section...]
//
// Examples:
//
//	# Run all §8.5 tests against a proxy on localhost:8443
//	rfc9113spec -host 127.0.0.1 -port 8443 -skip-verify
//
//	# Run only test #3 in §8.5 (like h2spec)
//	rfc9113spec -host 127.0.0.1 -port 8443 -skip-verify 8.5/3
//
//	# Emit a JUnit report for CI
//	rfc9113spec -host 127.0.0.1 -port 8443 -skip-verify -junit-report report.xml
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
	"rfc9298spec/sections/rfc9113"
)

func main() {
	host := flag.String("host", "127.0.0.1", "proxy host")
	port := flag.Int("port", 8443, "proxy port")
	skipVerify := flag.Bool("skip-verify", false, "skip TLS certificate verification")
	timeout := flag.Duration("timeout", 5*time.Second, "per-test timeout")
	verbose := flag.Bool("verbose", false, "show extra failure detail")
	dryRun := flag.Bool("dry-run", false, "list tests without executing them")
	tcpTargetHost := flag.String("tcp-target-host", "127.0.0.1", "target host for TCP echo (auto-started)")
	tcpTargetPort := flag.Int("tcp-target-port", 0, "target port for TCP echo (0 = auto-assign)")
	junitReport := flag.String("junit-report", "", "write JUnit XML report to this file")
	flag.Parse()

	// Section filter and optional case filter from positional arguments.
	// Syntax: "8.5"    – run all tests in §8.5
	//         "8.5/3"  – run only test #3 in §8.5 (like h2spec)
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

	// Start the built-in HTTPS/H2 target so data-plane tests have a real HTTP/2 server.
	h2Addr, stopH2, err := spec.StartH2Target(*tcpTargetHost, *tcpTargetPort)
	if err != nil {
		log.Fatalf("failed to start HTTPS/H2 target: %v", err)
	}
	defer stopH2()

	tcpHost, tcpPortStr, _ := net.SplitHostPort(h2Addr)
	tcpPort := 0
	fmt.Sscanf(tcpPortStr, "%d", &tcpPort)
	fmt.Fprintf(os.Stderr, "HTTPS/H2 target listening on %s\n\n", h2Addr)

	cfg := &config.Config{
		Host:          *host,
		Port:          *port,
		TLSSkipVerify: *skipVerify,
		Timeout:       *timeout,
		Verbose:       *verbose,
		DryRun:        *dryRun,
		TCPTargetHost: tcpHost,
		TCPTargetPort: tcpPort,
		Sections:      sectionFilter,
		CaseFilters:   caseFilters,
	}

	groups := []*spec.TestGroup{
		rfc9113.NewGroup(),
	}

	fmt.Printf("RFC 9113 §8.5 – The CONNECT Method (TCP over HTTP/2) – Conformance Test Suite\n")
	fmt.Printf("  proxy      : %s\n", cfg.Addr())
	fmt.Printf("  tcp target : %s\n\n", cfg.TCPTargetAddr())

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

