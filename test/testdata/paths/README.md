# Adversarial path corpus

`corpus.tsv` is the shared expectation table for ALLSEER's path matcher. It is
hand-written, not captured: every line exists because someone could plausibly
use that spelling to make a narrow grant cover something it should not, or to
make a denial miss something it should catch.

It is loaded by `internal/validator/path_corpus_test.go`, which runs every line
against `validator.MatchPath`, `validator.ValidatePattern`, and
`validator.IsResolved`. The semantics the table encodes are specified in
[`docs/path-matching.md`](../../../docs/path-matching.md); when the two
disagree, the specification is right and one of the other two is a bug.

## Format

Three tab-separated fields per line. `#` starts a comment line; blank lines are
skipped.

```
<expect>	<pattern>	<path>
```

| `<expect>` | Assertion |
|---|---|
| `match` | `MatchPath(pattern, path)` is true |
| `nomatch` | `MatchPath(pattern, path)` is false |
| `invalid` | `ValidatePattern(pattern)` returns an error, and nothing matches |
| `unresolved` | `IsResolved(path)` is false, and nothing matches |

`invalid` and `unresolved` are distinct from `nomatch` on purpose. All three
produce a false from `Match`, but only `nomatch` means "the envelope was
evaluated and did not cover this". The other two mean the question could not be
answered, which upstream must surface as `ViolationUnresolvable` rather than as
`ViolationSelectorMismatch` -- one says the agent did something unexpected, the
other says the system does not know what the agent did.

## What is deliberately not here

Two families of case cannot be reviewed as text, so they live in Go with the
bytes spelled out:

- **Unicode normalization and homoglyphs** -- `TestMatchUnicode` in
  `internal/validator/path_test.go`. NFC and NFD spellings of `café` are
  visually identical in this file, so a reader could not tell whether the
  fixture tests anything. The Go test writes `é` and `é`.
- **Symlink chains and symlinked roots** -- `TestWithinRootSymlinkedRoot`, which
  builds a real directory tree in `t.TempDir()`. It skips on hosts that refuse
  symlink creation, which includes most Windows configurations.

## Adding cases

Add the line under the section it belongs to, with a comment naming the escape
it tests. A case with no comment is not worth keeping: the point of the corpus
is that the next reader can tell what each line is defending against without
reconstructing it from the pattern.
