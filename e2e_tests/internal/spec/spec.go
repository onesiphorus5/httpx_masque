// Package spec provides the core test-framework types: TestGroup, TestCase,
// TestResult, and the Reporter interface — modelled after h2spec.
package spec

import (
	"errors"
	"time"

	"rfc9298spec/internal/config"
)

// Sentinel errors returned by test Run functions.
var (
	ErrTimeout = errors.New("test timed out")
	ErrSkipped = errors.New("test skipped")
)

// ─── Reporter ──────────────────────────────────────────────────────────────

// Reporter receives structured callbacks as tests execute.
type Reporter interface {
	BeginGroup(g *TestGroup)
	EndGroup(g *TestGroup)
	BeginTest(g *TestGroup, tc *TestCase, seq int)
	EndTest(g *TestGroup, tc *TestCase, result *TestResult)
}

// ─── TestResult ────────────────────────────────────────────────────────────

// TestResult records the outcome of a single test execution.
type TestResult struct {
	Skipped  bool
	Failed   bool
	Error    error
	Duration time.Duration
}

// ─── TestCase ──────────────────────────────────────────────────────────────

// TestCase is a single conformance assertion extracted from the RFC.
type TestCase struct {
	// Desc is a human-readable description of what is being tested.
	Desc string
	// Requirement quotes or paraphrases the normative RFC text (MUST/SHALL/…).
	Requirement string
	// Run executes the test and returns nil on success, ErrSkipped to skip, or
	// any other error to report a failure.
	Run func(cfg *config.Config) error

	// Result is set after the test has been executed.
	Result *TestResult
}

// ─── TestGroup ─────────────────────────────────────────────────────────────

// TestGroup is a collection of test cases corresponding to one RFC section.
type TestGroup struct {
	// Key is the short identifier used in paths, e.g. "3.2".
	Key string
	// Section is the RFC section number for display, e.g. "3.2".
	Section string
	// Name is the human-readable section title.
	Name string

	Parent *TestGroup
	Groups []*TestGroup
	Tests  []*TestCase

	PassedCount  int
	FailedCount  int
	SkippedCount int
}

// AddGroup appends a child group and sets its Parent.
func (g *TestGroup) AddGroup(child *TestGroup) {
	child.Parent = g
	g.Groups = append(g.Groups, child)
}

// AddTest appends a test case.
func (g *TestGroup) AddTest(tc *TestCase) {
	g.Tests = append(g.Tests, tc)
}

// ID returns the full dot-path of this group, e.g. "3/3.2".
func (g *TestGroup) ID() string {
	if g.Parent != nil && g.Parent.Key != "" {
		return g.Parent.ID() + "/" + g.Key
	}
	return g.Key
}

// Test runs all test cases in this group and every child group, reporting
// results via r.
func (g *TestGroup) Test(cfg *config.Config, r Reporter) {
	r.BeginGroup(g)

	for i, tc := range g.Tests {
		seqNum := i + 1
		// Case filter: if a specific case number is requested for this section,
		// skip all other cases (count them as skipped).
		if n, ok := cfg.CaseFilters[g.Section]; ok && seqNum != n {
			r.EndTest(g, tc, &TestResult{Skipped: true})
			g.SkippedCount++
			continue
		}
		result := g.run(cfg, tc, seqNum)
		r.EndTest(g, tc, result)

		if result.Skipped {
			g.SkippedCount++
		} else if result.Failed {
			g.FailedCount++
		} else {
			g.PassedCount++
		}
	}

	for _, child := range g.Groups {
		child.Test(cfg, r)
		g.PassedCount += child.PassedCount
		g.FailedCount += child.FailedCount
		g.SkippedCount += child.SkippedCount
	}

	r.EndGroup(g)
}

func (g *TestGroup) run(cfg *config.Config, tc *TestCase, seq int) *TestResult {
	if cfg.DryRun {
		return &TestResult{Skipped: true}
	}

	done := make(chan error, 1)
	go func() { done <- tc.Run(cfg) }()

	start := time.Now()
	var err error
	select {
	case err = <-done:
	case <-time.After(cfg.Timeout):
		err = ErrTimeout
	}

	result := &TestResult{Duration: time.Since(start)}
	switch {
	case errors.Is(err, ErrSkipped):
		result.Skipped = true
	case err != nil:
		result.Failed = true
		result.Error = err
	}
	tc.Result = result
	return result
}

// Totals aggregates results across an entire slice of top-level groups.
func Totals(groups []*TestGroup) (passed, failed, skipped int) {
	for _, g := range groups {
		passed += g.PassedCount
		failed += g.FailedCount
		skipped += g.SkippedCount
	}
	return
}
