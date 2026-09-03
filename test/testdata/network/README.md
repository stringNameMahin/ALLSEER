# Adversarial network corpus

`corpus.tsv` is the expectation table for ALLSEER's host matcher. Like the path
corpus it is hand-written: every line exists because someone could plausibly use
that spelling to make a network grant cover a destination it should not, or to
make a denial miss one it should catch.

It is loaded by `internal/validator/network_corpus_test.go` and run against
`validator.MatchHost`, `validator.ValidateHostPattern`, and
`validator.CorrelationMissing`. The semantics it encodes are specified in
[`docs/network-matching.md`](../../../docs/network-matching.md); when the two
disagree, the specification is right.

## Format

Three tab-separated fields per line. `#` starts a comment line; blank lines are
skipped.

```
<expect>	<pattern>	<host-or-ip>
```

| `<expect>` | Assertion |
|---|---|
| `match` | `MatchHost(pattern, host)` is true |
| `nomatch` | `MatchHost` is false, the pattern is valid, and the two were comparable |
| `invalid` | `ValidateHostPattern(pattern)` returns an error, and nothing matches |
| `uncorrelated` | `MatchHost` is false **and** `CorrelationMissing` is true |

`uncorrelated` is the distinction the module exists for. All three of `nomatch`,
`invalid`, and `uncorrelated` produce a false, but they are different findings:

- `nomatch` -- the envelope was evaluated and did not cover this destination.
- `uncorrelated` -- the envelope names hosts and we never learned this address's
  name. Escalates to the risk engine rather than reporting as a violation.
- `invalid` -- the selector could not be interpreted at all, which is an
  envelope defect and should have been caught at admission.

The test asserts `CorrelationMissing` is false on every `match` and `nomatch`
line as well, so a genuine mismatch can never be explained away as telemetry
trouble.

## What is deliberately not here

**Port cases.** `MatchPort` takes a list, which a three-column format cannot
express. They live in `TestMatchPort`, including the one that matters: an empty
list means *any* port, not *no* ports.

## Adding cases

Add the line under the section it belongs to, with a comment naming the
confusion it defends against -- suffix collision, family mismatch, wildcard
depth, correlation gap. A line whose purpose is not stated is not worth
keeping.
