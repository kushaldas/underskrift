#!/usr/bin/env bash
# gen-test-fixtures.sh — Generate test PKI fixtures for underskrift tests
#
# Creates a self-signed Root CA, an Intermediate (Signing) CA, and a
# signer certificate + PKCS#12 bundle. These are throwaway test-only
# keys and should NOT be used for anything real.
#
# Usage:
#   cd underskrift/tests/fixtures
#   bash ../../gen-test-fixtures.sh
#
# Output files (in current directory):
#   ca_cert.pem              - Root CA certificate (public)
#   ca_key.pem               - Root CA private key (DO NOT COMMIT)
#   intermediate_ca_cert.pem - Intermediate CA certificate (public)
#   signer_cert.pem          - End-entity signer certificate (public)
#   signer_key.pem           - Signer private key (DO NOT COMMIT)
#   signer.p12               - PKCS#12 bundle with signer key+cert+chain (DO NOT COMMIT)
#   chain.pem                - Full certificate chain (signer + intermediate + root)
#   ca_cert.srl              - OpenSSL serial file (artifact)

set -euo pipefail

PASSWORD="${PKCS12_PASSWORD:-test123}"
DAYS=3650  # 10 years — these are test-only

echo "=== Generating Root CA ==="
openssl genrsa -out ca_key.pem 2048
openssl req -new -x509 \
    -key ca_key.pem \
    -out ca_cert.pem \
    -days "$DAYS" \
    -utf8 -batch \
    -subj "/O=Kushal's CA/CN=Kushal's Root CA"

echo "=== Generating Intermediate (Signing) CA ==="
openssl genrsa -out intermediate_ca_key.pem 2048
openssl req -new \
    -key intermediate_ca_key.pem \
    -out intermediate_ca.csr \
    -utf8 -batch \
    -subj "/O=Kushal's CA/CN=Kushal's Signing CA"

# Sign intermediate CA cert with root CA (with CA:TRUE constraint)
openssl x509 -req \
    -in intermediate_ca.csr \
    -CA ca_cert.pem \
    -CAkey ca_key.pem \
    -CAcreateserial \
    -out intermediate_ca_cert.pem \
    -days "$DAYS" \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")

echo "=== Generating Signer Certificate ==="
openssl genrsa -out signer_key.pem 2048
openssl req -new \
    -key signer_key.pem \
    -out signer.csr \
    -utf8 -batch \
    -subj "/O=Kushal's CA/CN=Test Document Signer"

# Sign signer cert with intermediate CA
openssl x509 -req \
    -in signer.csr \
    -CA intermediate_ca_cert.pem \
    -CAkey intermediate_ca_key.pem \
    -CAcreateserial \
    -out signer_cert.pem \
    -days "$DAYS" \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n")

echo "=== Building certificate chain ==="
cat signer_cert.pem intermediate_ca_cert.pem ca_cert.pem > chain.pem

echo "=== Creating PKCS#12 bundle (legacy format for p12 crate) ==="
openssl pkcs12 -export -legacy \
    -inkey signer_key.pem \
    -in signer_cert.pem \
    -certfile intermediate_ca_cert.pem \
    -out signer.p12 \
    -passout "pass:${PASSWORD}"

# An enveloping CMS written by an implementation that shares no code with
# underskrift. Tests that only ever read our own output cannot catch a wrong
# reading of somebody else's, and this is the cheapest honest stand-in for the
# third-party signers (Dike, ArubaSign, …) whose files have to be composed onto
# in production. Note openssl writes signatureAlgorithm as plain rsaEncryption
# per RFC 3370 §3.2 — a shape our verifier used to reject.
echo "=== Signing a CMS envelope with openssl (foreign producer) ==="
openssl cms -sign -binary -nodetach -md sha256 \
    -in sample.pdf \
    -signer signer_cert.pem \
    -inkey signer_key.pem \
    -certfile intermediate_ca_cert.pem \
    -outform DER \
    -out foreign_envelope.p7m

echo "=== Cleaning up intermediate artifacts ==="
rm -f intermediate_ca.csr signer.csr intermediate_ca_cert.srl

echo ""
echo "=== Generated test fixtures ==="
echo "  Root CA cert:            ca_cert.pem"
echo "  Root CA key:             ca_key.pem  (DO NOT COMMIT)"
echo "  Intermediate CA cert:    intermediate_ca_cert.pem"
echo "  Intermediate CA key:     intermediate_ca_key.pem  (DO NOT COMMIT)"
echo "  Signer cert:             signer_cert.pem"
echo "  Signer key:              signer_key.pem  (DO NOT COMMIT)"
echo "  PKCS#12 bundle:          signer.p12  (DO NOT COMMIT, password: ${PASSWORD})"
echo "  Full chain:              chain.pem"
echo "  Foreign CMS envelope:    foreign_envelope.p7m  (signed by openssl, not by us)"
echo ""
echo "Run tests with: cd ../.. && cargo test --all-features"
