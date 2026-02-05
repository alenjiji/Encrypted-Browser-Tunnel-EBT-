#!/bin/bash
# Phase 4 Threat Model Enforcement
# Fails CI if Phase 4 invariants are violated

echo "=== Phase 4 Threat Model Checks ==="

echo "Checking for TLS payload inspection..."
if grep -r --include="*.rs" -E "(tls_payload|decrypt_payload|inspect.*tls|parse.*tls_data)" src/ >/dev/null 2>&1; then
    echo "ERROR: TLS payload inspection detected - violates Phase 4 invariants"
    exit 1
fi

echo "Checking for HTTP parsing after CONNECT..."
if grep -r --include="*.rs" "CONNECT" src/ \
  | grep -E "(parse.*http|http.*parse|HttpRequest|HttpResponse)" \
  | grep -v "handle_http_request" >/dev/null 2>&1; then
    echo "ERROR: HTTP parsing after CONNECT detected - violates Phase 4 invariants"
    exit 1
fi

echo "Checking for destination domain/IP logging..."
if grep -r --include="*.rs" -E "(log.*host|log.*domain|log.*destination|println.*host|println.*domain)" src/ \
  | grep -v "LEAK ANNOTATION" >/dev/null 2>&1; then
    echo "ERROR: Destination identifier logging detected - violates Phase 4 invariants"
    exit 1
fi

echo "✅ All Phase 4 threat model checks passed"