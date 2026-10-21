#!/bin/sh
# Throwaway CA + server cert for redis-tls (SAN: localhost, 127.0.0.1). Output: infra/certs/ (gitignored).
set -eu
cd "$(dirname "$0")"
mkdir -p certs
cd certs
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=horus-infra local CA" \
  -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout redis.key -out redis.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > redis.ext
openssl x509 -req -in redis.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 \
  -extfile redis.ext -out redis.crt 2>/dev/null
rm -f redis.csr redis.ext ca.srl
# The redis container runs as a non-root user; the key is throwaway.
chmod 644 redis.key
echo "certs written to $(pwd)"
