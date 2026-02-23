// Package reporter provides a terminal reporter that mimics h2spec's output
// style: hierarchical tree with colour-coded pass/fail/skip indicators, a
// per-failure detail block, and a summary line.
package reporter

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"rfc9298spec/internal/spec"
)

// ─── ANSI colour codes ─────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
	ansiGray   = "\033[90m"
)

func colored(s, code string) string {
	if !isTerminal() {
		return s
	}
	return code + s + ansiReset
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ─── ConsoleReporter ───────────────────────────────────────────────────────

// ConsoleReporter prints a tree of results to w (typically os.Stdout).
type ConsoleReporter struct {
	w      io.Writer
	depth  int
	failed []*failureRecord
}

type failureRecord struct {
	group  *spec.TestGroup
	tc     *spec.TestCase
	result *spec.TestResult
	seq    int
}

// New returns a ConsoleReporter writing to w.
func New(w io.Writer) *ConsoleReporter {
	return &ConsoleReporter{w: w}
}

func (r *ConsoleReporter) indent() string {
	return strings.Repeat("  ", r.depth)
}

// BeginGroup prints the group heading.
func (r *ConsoleReporter) BeginGroup(g *spec.TestGroup) {
	label := fmt.Sprintf("%s %s", colored(g.Section, ansiBold+ansiCyan), g.Name)
	fmt.Fprintf(r.w, "%s%s\n", r.indent(), label)
	r.depth++
}

// EndGroup decrements the indent.
func (r *ConsoleReporter) EndGroup(_ *spec.TestGroup) {
	r.depth--
}

// BeginTest is a no-op for the console reporter (we print in EndTest).
func (r *ConsoleReporter) BeginTest(_ *spec.TestGroup, _ *spec.TestCase, _ int) {}

// EndTest prints a single test result line.
func (r *ConsoleReporter) EndTest(g *spec.TestGroup, tc *spec.TestCase, result *spec.TestResult) {
	var icon, label string
	switch {
	case result.Skipped:
		icon = colored("-", ansiYellow)
		label = colored(tc.Desc, ansiGray)
	case result.Failed:
		icon = colored("×", ansiRed)
		label = colored(tc.Desc, ansiRed)
		r.failed = append(r.failed, &failureRecord{group: g, tc: tc, result: result})
	default:
		icon = colored("✓", ansiGreen)
		label = tc.Desc
	}
	dur := colored(fmt.Sprintf("(%dms)", result.Duration.Milliseconds()), ansiGray)
	fmt.Fprintf(r.w, "%s%s %s %s\n", r.indent(), icon, label, dur)
}

// PrintSummary prints the failure detail block and the final tally.
func (r *ConsoleReporter) PrintSummary(groups []*spec.TestGroup) {
	passed, failed, skipped := spec.Totals(groups)

	if len(r.failed) > 0 {
		fmt.Fprintf(r.w, "\n%s\n", colored("Failures:", ansiBold+ansiRed))
		for i, f := range r.failed {
			fmt.Fprintf(r.w, "\n  %d) %s %s\n",
				i+1,
				colored(f.group.Section, ansiBold),
				f.tc.Desc,
			)
			if f.tc.Requirement != "" {
				fmt.Fprintf(r.w, "     %s\n", colored("Requirement:", ansiGray))
				for _, line := range strings.Split(f.tc.Requirement, "\n") {
					fmt.Fprintf(r.w, "       %s\n", colored(strings.TrimSpace(line), ansiGray))
				}
			}
			if f.result.Error != nil {
				fmt.Fprintf(r.w, "     %s %s\n",
					colored("Error:", ansiRed),
					f.result.Error,
				)
			}
		}
	}

	fmt.Fprintln(r.w)
	fmt.Fprintf(r.w, "%s: %s  %s  %s\n",
		colored("Results", ansiBold),
		colored(fmt.Sprintf("%d passed", passed), ansiGreen),
		colored(fmt.Sprintf("%d failed", failed), ansiRed),
		colored(fmt.Sprintf("%d skipped", skipped), ansiYellow),
	)
}

// ─── JUnit XML reporter ────────────────────────────────────────────────────

type jFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type jSkipped struct{}

type jTestCase struct {
	XMLName   xml.Name `xml:"testcase"`
	Name      string   `xml:"name,attr"`
	Classname string   `xml:"classname,attr"`
	Time      float64  `xml:"time,attr"`
	Failure   *jFailure `xml:"failure,omitempty"`
	Skipped   *jSkipped `xml:"skipped,omitempty"`
}

type jSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []jTestCase `xml:"testcase"`
}

type jSuites struct {
	XMLName xml.Name `xml:"testsuites"`
	Suites  []jSuite
}

// JUnitReport writes a JUnit XML report to path.
func JUnitReport(path string, groups []*spec.TestGroup) error {

	var suites jSuites

	var walk func(g *spec.TestGroup)
	walk = func(g *spec.TestGroup) {
		suite := jSuite{
			Name:     fmt.Sprintf("%s %s", g.Section, g.Name),
			Failures: g.FailedCount,
			Skipped:  g.SkippedCount,
		}
		for _, tc := range g.Tests {
			jc := jTestCase{
				Name:      tc.Desc,
				Classname: fmt.Sprintf("rfc9298.%s", g.Section),
			}
			if tc.Result != nil {
				jc.Time = tc.Result.Duration.Seconds()
				if tc.Result.Skipped {
					jc.Skipped = &jSkipped{}
				} else if tc.Result.Failed && tc.Result.Error != nil {
					jc.Failure = &jFailure{
						Message: tc.Result.Error.Error(),
						Text:    tc.Requirement,
					}
				}
			}
			suite.Cases = append(suite.Cases, jc)
			suite.Tests++
		}
		suites.Suites = append(suites.Suites, suite)
		for _, child := range g.Groups {
			walk(child)
		}
	}
	for _, g := range groups {
		walk(g)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := xml.NewEncoder(f)
	enc.Indent("", "  ")
	return enc.Encode(suites)
}
