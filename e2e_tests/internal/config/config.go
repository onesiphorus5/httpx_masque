// Package config holds the runtime configuration for the rfc9298spec test runner.
package config

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)


// Config is the configuration passed to every test case.
type Config struct {
	// Proxy address.
	Host string
	Port int

	// Skip TLS certificate verification.
	TLSSkipVerify bool

	// Per-test timeout.
	Timeout time.Duration

	// Verbose prints extra detail on failures.
	Verbose bool

	// DryRun lists tests without executing them.
	DryRun bool

	// Target host/port for UDP proxying tests (RFC 9298).
	// The test suite starts its own UDP echo server at this address.
	TargetHost string
	TargetPort int

	// TCPTargetHost / TCPTargetPort for TCP CONNECT tests (RFC 9113 §8.5,
	// RFC 9114 §4.4).  The test suite starts its own TCP echo server here.
	TCPTargetHost string
	TCPTargetPort int

	// URI template path used for connect-udp requests.
	// Must contain {target_host} and {target_port}.
	// Default: "/.well-known/masque/udp/{target_host}/{target_port}/"
	PathTemplate string

	// Section filter: if non-empty, only run tests whose section prefix matches.
	Sections []string

	// CaseFilters maps a section identifier to a specific 1-based test case
	// index.  When set, only that test case is run within matching groups.
	// Populated by the "section/N" positional argument syntax.
	CaseFilters map[string]int

	// ReferenceHost / ReferencePort for the reference proxy H2 (TCP) endpoint
	// (e.g. envoy H2).  ReferencePort == 0 means no H2 reference.
	ReferenceHost string
	ReferencePort int

	// ReferenceH3Host / ReferenceH3Port for the reference proxy H3 (QUIC)
	// endpoint (e.g. envoy H3).  ReferenceH3Port == 0 means no H3 reference.
	ReferenceH3Host string
	ReferenceH3Port int
}

// Addr returns "host:port".
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// TargetAddr returns "targetHost:targetPort" for the UDP echo server.
func (c *Config) TargetAddr() string {
	return fmt.Sprintf("%s:%d", c.TargetHost, c.TargetPort)
}

// TCPTargetAddr returns "tcpTargetHost:tcpTargetPort" for the TCP echo server.
func (c *Config) TCPTargetAddr() string {
	return fmt.Sprintf("%s:%d", c.TCPTargetHost, c.TCPTargetPort)
}

// BuildPath expands the URI template for the given target host and port.
func (c *Config) BuildPath(host string, port int) string {
	tmpl := c.PathTemplate
	if tmpl == "" {
		tmpl = "/.well-known/masque/udp/{target_host}/{target_port}/"
	}
	tmpl = strings.ReplaceAll(tmpl, "{target_host}", url.PathEscape(host))
	tmpl = strings.ReplaceAll(tmpl, "{target_port}", strconv.Itoa(port))
	return tmpl
}

// TLSConfig builds a *tls.Config for connecting to the proxy with ALPN "h2".
func (c *Config) TLSConfig() *tls.Config {
	return &tls.Config{
		ServerName:         c.Host,
		InsecureSkipVerify: c.TLSSkipVerify, //nolint:gosec
		NextProtos:         []string{"h2"},
	}
}

// RunWithRef runs testFn against the DUT and, when cfg.HasReference(), also
// against the reference proxy. Returns nil iff both produce the same passing
// outcome. Use this to add differential testing to any HTTP/2 test case.
func RunWithRef(cfg *Config, testFn func(*Config) error) error {
	dutErr := testFn(cfg)
	if !cfg.HasReference() {
		return dutErr
	}
	refErr := testFn(cfg.WithReference())
	return CompareOutcomes(dutErr, refErr)
}

// RunWithRefH3 runs testFn against the DUT and, when cfg.HasH3Reference(),
// also against the H3 reference proxy.  Use this to add differential testing
// to any HTTP/3 test case.
func RunWithRefH3(cfg *Config, testFn func(*Config) error) error {
	dutErr := testFn(cfg)
	if !cfg.HasH3Reference() {
		return dutErr
	}
	refErr := testFn(cfg.WithH3Reference())
	return CompareOutcomes(dutErr, refErr)
}

// CompareOutcomes returns nil when DUT and reference both passed or both
// failed, and an explanatory error when their outcomes diverge.
func CompareOutcomes(dutErr, refErr error) error {
	switch {
	case (dutErr == nil) == (refErr == nil):
		return dutErr // same outcome — return DUT's own result
	case dutErr != nil && refErr == nil:
		return fmt.Errorf("DUT failed but reference passed: %w", dutErr)
	default:
		return fmt.Errorf("DUT passed but reference failed (ref err: %v)", refErr)
	}
}

// HasReference returns true when a reference H2 proxy port has been configured.
func (c *Config) HasReference() bool {
	return c.ReferencePort > 0
}

// ReferenceAddr returns "referenceHost:referencePort".
func (c *Config) ReferenceAddr() string {
	return fmt.Sprintf("%s:%d", c.ReferenceHost, c.ReferencePort)
}

// WithReference returns a shallow copy with Host/Port replaced by the
// reference H2 proxy address, so the same test function can be called against it.
func (c *Config) WithReference() *Config {
	cp := *c
	cp.Host = c.ReferenceHost
	cp.Port = c.ReferencePort
	return &cp
}

// HasH3Reference returns true when a reference H3 proxy port has been configured.
func (c *Config) HasH3Reference() bool {
	return c.ReferenceH3Port > 0
}

// ReferenceH3Addr returns "referenceH3Host:referenceH3Port".
func (c *Config) ReferenceH3Addr() string {
	return fmt.Sprintf("%s:%d", c.ReferenceH3Host, c.ReferenceH3Port)
}

// WithH3Reference returns a shallow copy with Host/Port replaced by the
// reference H3 proxy address, so the same test function can be called against it.
func (c *Config) WithH3Reference() *Config {
	cp := *c
	cp.Host = c.ReferenceH3Host
	cp.Port = c.ReferenceH3Port
	return &cp
}

// ShouldRunSection returns true if the test section should be included in the
// current run based on the Sections filter.
func (c *Config) ShouldRunSection(section string) bool {
	if len(c.Sections) == 0 {
		return true
	}
	for _, s := range c.Sections {
		if strings.HasPrefix(section, s) || strings.HasPrefix(s, section) {
			return true
		}
	}
	return false
}
