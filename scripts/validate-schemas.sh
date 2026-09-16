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
  echo "check-jsonschema not found. Install with one of:"
  echo "    sudo apt-get install python3-check-jsonschema"
  echo "    pip install check-jsonschema"
  echo "skipping schema validation"
  echo ""
  echo "NOTE: this skip is not a pass. Every example in api/schema/examples/"
  echo "went unvalidated for the life of this script because nobody had the"
  echo "tool installed, and one of them did not validate until 2026-09-16."
  echo "Install it."
  exit 0
fi

# The cross-file $refs are relative and the schemas carry absolute $id values,
# so a resolver treats them as remote and reaches for the network. Pointing the
# base URI at this directory resolves them to the sibling files instead.
BASE_URI="file://$(cd "$SCHEMA_DIR" && pwd)/"

fail=0

validate() {
  local schema="$1" doc="$2"
  if [[ ! -f "$doc" ]]; then
    echo "  MISSING: $doc"
    fail=1
    return
  fi
  printf '  %s ... ' "$(basename "$doc")"
  if check-jsonschema --base-uri "$BASE_URI" --schemafile "$schema" "$doc" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "FAILED"
    check-jsonschema --base-uri "$BASE_URI" --schemafile "$schema" "$doc" || true
    fail=1
  fi
}

echo ""
echo "Validating example documents:"
validate "$SCHEMA_DIR/ece.v1alpha1.schema.json" "$EXAMPLE_DIR/ece.example.json"

# Two decision documents rather than one, because the schema admits two shapes
# that differ in the field it is easiest to get wrong. The scored example is a
# real record lifted from test/testdata/golden/; the unscored one is what a
# stage failure produces, and it is the shape that was rejected by this schema
# until the wire format was settled.
validate "$SCHEMA_DIR/decision.v1alpha1.schema.json" "$EXAMPLE_DIR/decision.example.json"
validate "$SCHEMA_DIR/decision.v1alpha1.schema.json" "$EXAMPLE_DIR/decision.unscored.example.json"

validate "$SCHEMA_DIR/event.v1alpha1.schema.json" "$EXAMPLE_DIR/event.example.json"

echo ""
if [[ $fail -eq 0 ]]; then
  echo "All examples valid."
else
  echo "Validation failed."
  exit 1
fi
echo ""
