#!/bin/sh
set -e
NGHTTPX_PORT="${NGHTTPX_PORT:-8446}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-8444}"
openssl req -x509 -newkey rsa:2048 \
    -keyout /tmp/nghttpx.key -out /tmp/nghttpx.crt \
    -days 1 -nodes -subj "/CN=nghttpx-proxy" 2>/dev/null
exec nghttpx \
    --frontend="*,${NGHTTPX_PORT};tls" \
    --http2-proxy \
    --private-key-file=/tmp/nghttpx.key \
    --certificate-file=/tmp/nghttpx.crt \
    --backend="${TARGET_HOST},${TARGET_PORT};no-tls" \
    --no-ocsp \
    --errorlog-syslog=no
