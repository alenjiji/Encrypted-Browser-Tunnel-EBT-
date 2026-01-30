#!/bin/bash
# Phase 4 Threat Model Enforcement
# Fails CI if Phase 4 invariants are violated

set -e

echo "=== Phase 4 Threat Model Checks ==="

# Check for TLS payload inspection
echo "Checking for TLS payload inspection..."
if grep -r --include="*.rs" -E "(tls_payload|decrypt_payload|inspect.*tls|parse.*tls_data)" src/; then
    echo "ERROR: TLS payload inspection detected - violates Phase 4 invariants"
    exit 1
fi

# Check for HTTP parsing after CONNECT
echo "Checking for HTTP parsing after CONNECT..."
if grep -r --include="*.rs" -A 10 -B 5 "CONNECT" src/ | grep -E "(parse.*http|http.*parse|HttpRequest|HttpResponse)" | grep -v "handle_http_request"; then
    echo "ERROR: HTTP parsing after CONNECT detected - violates Phase 4 invariants"
    exit 1
fi

# Check for destination logging
echo "Checking for destination domain/IP logging..."
if grep -r --include="*.rs" -E "(log.*host|log.*domain|log.*destination|println.*host|println.*domain)" src/ | grep -v "// LEAK ANNOTATION"; then
    echo "ERROR: Destination identifier logging detected - violates Phase 4 invariants"
    exit 1
fi

echo "✅ All Phase 4 threat model checks passed"