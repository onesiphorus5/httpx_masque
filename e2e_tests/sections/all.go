// Package sections aggregates all RFC 9298 test groups.
package sections

import (
	"rfc9298spec/internal/spec"
	"rfc9298spec/sections/rfc9113"
	"rfc9298spec/sections/rfc9114"
	"rfc9298spec/sections/section3"
	"rfc9298spec/sections/section4"
	"rfc9298spec/sections/section5"
)

// All returns the full list of top-level test groups in RFC section order.
func All() []*spec.TestGroup {
	return []*spec.TestGroup{
		section3.NewGroup(),
		section4.NewGroup(),
		section5.NewGroup(),
		rfc9113.NewGroup(),
		rfc9114.NewGroup(),
	}
}
