// Package section3 registers all RFC 9298 §3 test groups.
//
// §3 Client and Proxy Behavior covers:
//   - §3.1  UDP Proxy Handling
//   - §3.4  HTTP/2 and HTTP/3 Requests
//   - §3.5  HTTP/2 and HTTP/3 Responses
//
// Each sub-section is split into an "HTTP/2" and "HTTP/3" child group.
package section3

import "rfc9298spec/internal/spec"

// NewGroup returns the top-level §3 TestGroup.
func NewGroup() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "3",
		Section: "3",
		Name:    "Client and Proxy Behavior",
	}
	g.AddGroup(makeSection31())
	g.AddGroup(makeSection34())
	g.AddGroup(makeSection35())
	return g
}

func makeSection31() *spec.TestGroup {
	g := &spec.TestGroup{Key: "3.1", Section: "3.1", Name: "UDP Proxy Handling"}
	g.AddGroup(newSection31H2())
	g.AddGroup(newSection31H3())
	return g
}

func makeSection34() *spec.TestGroup {
	g := &spec.TestGroup{Key: "3.4", Section: "3.4", Name: "HTTP/2 and HTTP/3 Requests"}
	g.AddGroup(newSection34H2())
	g.AddGroup(newSection34H3())
	return g
}

func makeSection35() *spec.TestGroup {
	g := &spec.TestGroup{Key: "3.5", Section: "3.5", Name: "HTTP/2 and HTTP/3 Responses"}
	g.AddGroup(newSection35H2())
	g.AddGroup(newSection35H3())
	return g
}
