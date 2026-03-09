BINARIES        := rfc9298spec rfc9113spec rfc9114spec
TARGET_IMAGE    := rfc9298-targets
TARGET_CONTAINER:= rfc9298-targets

# Ports exposed by the target-server container.
TARGET_H2_PORT  := 8444
TARGET_H3_PORT  := 8445

ENVOY_H2_PORT     := 8446
ENVOY_H3_PORT     := 8447
ENVOY_IMAGE       := envoy-proxy
ENVOY_CONTAINER   := envoy-proxy

.PHONY: all build test vet run run-9298 run-9113 run-9114 ci clean tidy \
        docker-build docker-start-targets docker-stop-targets \
        docker-build-envoy docker-start-envoy docker-stop-envoy \
        run-9298-docker run-9113-docker run-9114-docker run-docker \
        ci-docker help

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

# ── Local targets (auto-start servers on localhost) ─────────────────────────

## run-9298: run RFC 9298 suite against a local proxy (auto-starts HTTP/3 target)
run-9298: build
	./rfc9298spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-timeout 5s

## run-9113: run RFC 9113 §8.5 suite against a local proxy (auto-starts HTTPS/H2 target)
run-9113: build
	./rfc9113spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-timeout 5s

## run-9114: run RFC 9114 §4.4 suite against a local proxy (auto-starts HTTPS/H2 target)
run-9114: build
	./rfc9114spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-timeout 5s

## run: run all three suites (auto-start targets locally)
run: run-9298 run-9113 run-9114

## ci: build, vet, and emit JUnit reports (auto-start targets locally)
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

# ── Docker targets (target servers run in a container) ──────────────────────

## docker-build: build the target-server Docker image
docker-build:
	docker build -f Dockerfile.targets -t $(TARGET_IMAGE) .

## docker-start-targets: start the target-server container in the background
docker-start-targets: docker-build
	docker run --rm -d \
		--name $(TARGET_CONTAINER) \
		-p $(TARGET_H2_PORT):8444/tcp \
		-p $(TARGET_H3_PORT):8445/udp \
		$(TARGET_IMAGE)
	@echo "Waiting for target servers to be ready..."
	@sleep 2

## docker-stop-targets: stop and remove the target-server container
docker-stop-targets:
	docker stop $(TARGET_CONTAINER) 2>/dev/null || true

## docker-build-envoy: build the Envoy reference-proxy Docker image
docker-build-envoy:
	docker build -f Dockerfile.envoy -t $(ENVOY_IMAGE) .

## docker-start-envoy: start Envoy container (host network, H2 on 8446, H3 on 8447)
docker-start-envoy: docker-build-envoy
	docker run --rm -d \
		--network=host \
		--name $(ENVOY_CONTAINER) \
		-e ENVOY_H2_PORT=$(ENVOY_H2_PORT) \
		-e ENVOY_H3_PORT=$(ENVOY_H3_PORT) \
		$(ENVOY_IMAGE)
	@sleep 3

## docker-stop-envoy: stop the Envoy container
docker-stop-envoy:
	docker stop $(ENVOY_CONTAINER) 2>/dev/null || true

## run-9298-docker: run RFC 9298 suite using the Docker target container
run-9298-docker: build docker-start-targets docker-start-envoy
	./rfc9298spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-target-host 127.0.0.1 \
		-target-port $(TARGET_H3_PORT) \
		-ref-host 127.0.0.1 \
		-ref-port $(ENVOY_H2_PORT) \
		-ref-h3-host 127.0.0.1 \
		-ref-h3-port $(ENVOY_H3_PORT) \
		-timeout 5s; \
	$(MAKE) docker-stop-targets docker-stop-envoy

## run-9113-docker: run RFC 9113 §8.5 suite using the Docker target container
run-9113-docker: build docker-start-targets docker-start-envoy
	./rfc9113spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-tcp-target-host 127.0.0.1 \
		-tcp-target-port $(TARGET_H2_PORT) \
		-ref-host 127.0.0.1 \
		-ref-port $(ENVOY_H2_PORT) \
		-timeout 5s; \
	$(MAKE) docker-stop-targets docker-stop-envoy

## run-9114-docker: run RFC 9114 §4.4 suite using the Docker target container
run-9114-docker: build docker-start-targets docker-start-envoy
	./rfc9114spec \
		-host 127.0.0.1 \
		-port 8443 \
		-skip-verify \
		-tcp-target-host 127.0.0.1 \
		-tcp-target-port $(TARGET_H2_PORT) \
		-ref-host 127.0.0.1 \
		-ref-port $(ENVOY_H3_PORT) \
		-timeout 5s; \
	$(MAKE) docker-stop-targets docker-stop-envoy

## run-docker: run all three suites using a single Docker target container
run-docker: build docker-start-targets docker-start-envoy
	./rfc9298spec \
		-host 127.0.0.1 -port 8443 -skip-verify \
		-target-host 127.0.0.1 -target-port $(TARGET_H3_PORT) \
		-ref-host 127.0.0.1 -ref-port $(ENVOY_H2_PORT) \
		-ref-h3-host 127.0.0.1 -ref-h3-port $(ENVOY_H3_PORT) \
		-timeout 5s; \
	./rfc9113spec \
		-host 127.0.0.1 -port 8443 -skip-verify \
		-tcp-target-host 127.0.0.1 -tcp-target-port $(TARGET_H2_PORT) \
		-ref-host 127.0.0.1 -ref-port $(ENVOY_H2_PORT) \
		-timeout 5s; \
	./rfc9114spec \
		-host 127.0.0.1 -port 8443 -skip-verify \
		-tcp-target-host 127.0.0.1 -tcp-target-port $(TARGET_H2_PORT) \
		-ref-host 127.0.0.1 -ref-port $(ENVOY_H3_PORT) \
		-timeout 5s; \
	$(MAKE) docker-stop-targets docker-stop-envoy

## ci-docker: build, vet, emit JUnit reports using Docker target container
# Note: -ref-h3-port is intentionally omitted from ci-docker.  Envoy v1.32's
# HTTP/3 connect-udp UDP data-plane forwarding is incomplete (allow_extended_connect
# is "work-in-progress"), so using it as H3 reference in CI would produce false
# failures when the DUT correctly implements §3.1 H3 but envoy does not.
# Use run-9298-docker for manual differential testing with the H3 reference.
ci-docker: build docker-start-targets docker-start-envoy
	./rfc9298spec \
		-host 127.0.0.1 -port 8443 -skip-verify \
		-target-host 127.0.0.1 -target-port $(TARGET_H3_PORT) \
		-ref-host 127.0.0.1 -ref-port $(ENVOY_H2_PORT) \
		-junit-report report-9298.xml || true; \
	./rfc9113spec \
		-host 127.0.0.1 -port 8443 -skip-verify \
		-tcp-target-host 127.0.0.1 -tcp-target-port $(TARGET_H2_PORT) \
		-ref-host 127.0.0.1 -ref-port $(ENVOY_H2_PORT) \
		-junit-report report-9113.xml || true; \
	./rfc9114spec \
		-host 127.0.0.1 -port 8443 -skip-verify \
		-tcp-target-host 127.0.0.1 -tcp-target-port $(TARGET_H2_PORT) \
		-ref-host 127.0.0.1 -ref-port $(ENVOY_H3_PORT) \
		-junit-report report-9114.xml || true; \
	$(MAKE) docker-stop-targets docker-stop-envoy

# ── Housekeeping ─────────────────────────────────────────────────────────────

## clean: remove built binaries and reports
clean:
	rm -f $(BINARIES) report-9298.xml report-9113.xml report-9114.xml

## tidy: tidy go.mod/go.sum
tidy:
	go mod tidy

## help: print this help
help:
	@grep -E '^##' Makefile | sed 's/## /  /'
