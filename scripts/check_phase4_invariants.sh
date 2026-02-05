#!/bin/bash
# Phase 4 Threat Model Enforcement
# Fails CI if Phase 4 invariants are violated

echo "=== Phase 4 Threat Model Checks ==="

echo "Checking for TLS payload inspection..."
if grep -r -E "(tls_payload|decrypt_payload|inspect.*tls|parse.*tls_data)" src/*.rs >/dev/null 2>&1; then
    echo "ERROR: TLS payload inspection detected - violates Phase 4 invariants"
    exit 1
fi

echo "Checking for HTTP parsing after CONNECT..."
if grep -r "CONNECT" src/*.rs | grep -E "(parse.*http|http.*parse|HttpRequest|HttpResponse)" | grep -v "handle_http_request" >/dev/null 2>&1; then
    echo "ERROR: HTTP parsing after CONNECT detected - violates Phase 4 invariants"
    exit 1
fi

echo "Checking for destination domain/IP logging..."
if grep -r -E "(log.*host|log.*domain|log.*destination|println.*host|println.*domain)" src/*.rs | grep -v "LEAK ANNOTATION" >/dev/null 2>&1; then
    echo "ERROR: Destination identifier logging detected - violates Phase 4 invariants"
    exit 1
fi

echo "✅ All Phase 4 threat model checks passed"