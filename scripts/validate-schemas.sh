#!/usr/bin/env bash
# Validate example documents against the ALLSEER JSON schemas.
#
# The schemas are wire contracts between the daemon, the CLI, and any external
# consumer of the audit log. Validating the examples on every change is what
# keeps the documented format and the real format from drifting apart.
set -euo pipefail

SCHEMA_DIR="api/schema"
EXAMPLE_DIR="api/schema/examples"

if ! command -v check-jsonschema >/dev/null 2>&1; then
  echo "check-jsonschema not found, install with: pip install check-jsonschema"
  echo "skipping schema validation"
  exit 0
fi

fail=0

validate() {
  local schema="$1" doc="$2"
  if [[ ! -f "$doc" ]]; then
    echo "  MISSING: $doc"
    fail=1
    return
  fi
  printf '  %s ... ' "$(basename "$doc")"
  if check-jsonschema --schemafile "$schema" "$doc" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "FAILED"
    check-jsonschema --schemafile "$schema" "$doc" || true
    fail=1
  fi
}

echo ""
echo "Validating example documents:"
validate "$SCHEMA_DIR/ece.v1alpha1.schema.json" "$EXAMPLE_DIR/ece.example.json"

# TODO: event.example.json and decision.example.json are not written yet. Add
# them here once they exist; a missing example is reported as a failure so the
# gap stays visible rather than passing silently.

echo ""
if [[ $fail -eq 0 ]]; then
  echo "All examples valid."
else
  echo "Validation failed."
  exit 1
fi
echo ""
