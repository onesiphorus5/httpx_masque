#!/bin/sh
set -e
ENVOY_H2_PORT="${ENVOY_H2_PORT:-8446}"
ENVOY_H3_PORT="${ENVOY_H3_PORT:-8447}"

# Generate an ephemeral self-signed certificate for both listeners.
openssl req -x509 -newkey rsa:2048 \
    -keyout /tmp/envoy.key -out /tmp/envoy.crt \
    -days 1 -nodes -subj "/CN=envoy-proxy" 2>/dev/null

# Write the Envoy bootstrap configuration.
# Variables are expanded by the shell (no single-quoted heredoc delimiter).
cat > /tmp/envoy.yaml << ENVOY_CONFIG
static_resources:
  listeners:

  # ── HTTP/2 forward-proxy (TLS) ─────────────────────────────────────────────
  # Handles RFC 9113 §8.5 (TCP CONNECT) and RFC 9298 (connect-udp / MASQUE).
  - name: listener_h2
    address:
      socket_address:
        address: 0.0.0.0
        port_value: ${ENVOY_H2_PORT}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain: {filename: /tmp/envoy.crt}
              private_key: {filename: /tmp/envoy.key}
            alpn_protocols: [h2]
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: h2_proxy
          codec_type: HTTP2
          http2_protocol_options:
            allow_connect: true
          upgrade_configs:
          - upgrade_type: CONNECT
          - upgrade_type: connect-udp
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache_config
                dns_lookup_family: V4_ONLY
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: local_route_h2
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  connect_matcher: {}
                route:
                  cluster: dynamic_forward_proxy_cluster
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config: {}
                  - upgrade_type: connect-udp
                    connect_config: {}

  # ── HTTP/3 forward-proxy (QUIC) ────────────────────────────────────────────
  # Handles RFC 9114 §4.4 (TCP CONNECT over HTTP/3).
  - name: listener_h3
    address:
      socket_address:
        address: 0.0.0.0
        port_value: ${ENVOY_H3_PORT}
        protocol: UDP
    udp_listener_config:
      quic_options: {}
    filter_chains:
    - name: h3
      transport_socket:
        name: envoy.transport_sockets.quic
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.quic.v3.QuicDownstreamTransport
          downstream_tls_context:
            common_tls_context:
              tls_certificates:
              - certificate_chain: {filename: /tmp/envoy.crt}
                private_key: {filename: /tmp/envoy.key}
              alpn_protocols: [h3]
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: h3_proxy
          codec_type: HTTP3
          http3_protocol_options:
            allow_extended_connect: true
          upgrade_configs:
          - upgrade_type: CONNECT
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache_config
                dns_lookup_family: V4_ONLY
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: local_route_h3
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  connect_matcher: {}
                route:
                  cluster: dynamic_forward_proxy_cluster
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config: {}

  clusters:
  - name: dynamic_forward_proxy_cluster
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config:
          name: dynamic_forward_proxy_cache_config
          dns_lookup_family: V4_ONLY

admin:
  address:
    socket_address: {address: 127.0.0.1, port_value: 9901}
ENVOY_CONFIG

exec envoy -c /tmp/envoy.yaml \
    --log-level warn \
    --concurrency 2
