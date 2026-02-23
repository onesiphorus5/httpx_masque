BINARIES := rfc9298spec rfc9113spec rfc9114spec

.PHONY: all build test vet run run-section ci clean tidy help \
        run-9298 run-9113 run-9114

all: build

## build: compile all three test runners
build:
	go build -o rfc9298spec ./cmd/rfc9298spec
	go build -o rfc9113spec ./cmd/rfc9113spec
	go build -o rfc9114spec ./cmd/rfc9114spec

## test: compile-check all packages (no proxy required)
test:
	go build ./...
	go vet ./...

## vet: run go vet
vet:
	go vet ./...

## run-9298: run RFC 9298 suite against a local proxy
run-9298: build
	./rfc9298spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-timeout 5s

## run-9113: run RFC 9113 §8.5 suite against a local proxy
run-9113: build
	./rfc9113spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-timeout 5s

## run-9114: run RFC 9114 §4.4 suite against a local proxy
run-9114: build
	./rfc9114spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-timeout 5s

## run: run all three suites
run: run-9298 run-9113 run-9114

## ci: build, vet, and emit JUnit reports (for CI pipelines)
ci: build
	./rfc9298spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-junit-report report-9298.xml || true
	./rfc9113spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-junit-report report-9113.xml || true
	./rfc9114spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-junit-report report-9114.xml || true

## clean: remove built binaries and reports
clean:
	rm -f $(BINARIES) report-9298.xml report-9113.xml report-9114.xml

## tidy: tidy go.mod/go.sum
tidy:
	go mod tidy

## help: print this help
help:
	@grep -E '^##' Makefile | sed 's/## /  /'
