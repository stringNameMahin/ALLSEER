# Golden decision streams

The committed output of ALLSEER's deterministic core. One file per case:

| File | Recording | Envelope | Decisions |
|---|---|---|---|
| `git-operation.decisions.jsonl` | [`../replay/git-operation.jsonl`](../replay/git-operation.jsonl) | [`../envelopes/git-operation.json`](../envelopes/git-operation.json) | 10 |
| `credential-egress.decisions.jsonl` | [`../replay/credential-egress.jsonl`](../replay/credential-egress.jsonl) | [`../envelopes/credential-egress.json`](../envelopes/credential-egress.json) | 10 |

Each line is one `decision.Decision` exactly as
[`internal/audit`](../../../internal/audit/) writes it to a live audit log. The
files are produced by the real path -- replay source, validator, risk engine,
policy engine, session state, JSONL sink -- under the shipped
[`rules.default.yaml`](../../../configs/rules.default.yaml) and
[`sensitivity.default.yaml`](../../../configs/sensitivity.default.yaml). Nothing
about them is synthesized for the test.

## What they are for

This is the only place in the tree where the **composition** is pinned. Every
other test knows what one component should say; none of them knows what the
system concludes about a session, which is the thing the research question is
about. A change to a scorer weight, a rule priority, a verdict classification,
a matcher's semantics, or a serialized field name changes a file here, and
somebody has to look at the diff and decide whether that was intended.

Two of the twenty decisions are the reason the corpus exists:

- **`gt-008`** -- a write to `.github/workflows/`, denied by an envelope carve-out
  inside a workspace-wide write grant. Denials win over grants, and this is the
  proof they still do.
- **`ex-009`** -- a connection to an address no DNS answer covers, six events
  after a successful read of `~/.aws/credentials`. The sequence detector
  contributes 30 points and the decision reaches `request_approval`. Without
  that factor the same event scores low enough to be a warning, which is the
  clearest demonstration in the corpus that the composition finds something the
  parts do not.

Fourteen of the twenty are routine allows scoring zero. That is not filler: a
governance system that finds something in every event of an ordinary `git
commit` is a system nobody will leave enabled, and the false-positive floor is
as much a property worth pinning as the findings are.

## Regenerating

```
make golden
git diff -- test/testdata/golden/
```

Never by hand. An expected value edited to make a test pass is an assertion
that has stopped asserting anything.

`go test ./...` **compares and fails**; it never writes. Regeneration is a
separate, named action for that reason.

## Determinism

Byte-reproducible across runs, machines, and dates. Every field is deterministic
because the production semantics already made it so -- decision IDs derive from
event IDs, timestamps come from each event's own recorded wall clock, scores are
pure functions of the observation and the session history, and `encoding/json`
sorts map keys. Nothing is normalized away after the fact.

The one exception is `latency`, which measures the host rather than the session.
It is pinned to zero by injecting a stopped clock through `pipeline.Config.Now`
-- the seam the pipeline already documents as existing "so a replayed session
produces a reproducible record". Zero is the honest value for a replay: the
number that field reports is the delay charged to a live agent's syscall, and a
replay charges none.

## Line endings: LF, on every platform

These files are **LF-terminated and must stay that way**, on Windows as much as
anywhere else. `.gitattributes` at the repository root pins it:

```
test/testdata/golden/*.jsonl text eol=lf
```

### Why

They are not source. They are committed *output* -- the exact bytes
[`internal/audit.JSONLSink`](../../../internal/audit/) writes to a live audit
log -- and `TestGolden` compares them byte for byte. The sink emits LF and
nothing else, because the audit format is a wire contract with external tooling
and "one JSON object per line" has to mean the same thing on every host that
reads the log. A golden file with CRLF in it would no longer be a record of what
the writer produces.

This repository is developed on Windows with `core.autocrlf=true`, which is
right for source and wrong for these. Without the rule above, a fresh clone
smudges them to CRLF and the golden suite fails on a clean checkout:

```
--- FAIL: TestGoldenStreamIsWellFormed/git-operation
    the stream contains a carriage return; the audit writer emits LF only
```

That failure is **correct**, and it is why the fix belongs in `.gitattributes`
rather than anywhere else. Three things were deliberately *not* done:

- **The test was not taught to normalize CRLF.** It exists to enforce the
  canonical byte representation. A test that accepted either ending would stop
  detecting the one thing it is for.
- **The sink was not changed.** Emitting CRLF on Windows would make the audit
  format platform-dependent, which is precisely what a wire contract must not
  be.
- **No per-OS golden files.** Two goldens for one pipeline is two things to keep
  in agreement, and the whole point is that the deterministic core produces one
  answer.

### Why `text eol=lf` rather than `-text`

`-text` would also stop the conversion, and it is the wrong tool twice over:

- `text eol=lf` is **self-healing**. An editor or a tool that rewrites one of
  these files with CRLF has it normalized back on the way into the index, so the
  canonical form cannot be lost by accident. `-text` commits whatever bytes are
  on disk, which would break every other platform silently.
- `-text` marks a file **binary for diff**. `git diff -- test/testdata/golden/`
  reporting "Binary files differ" would destroy the review workflow these files
  exist for: a changed golden is a change in what the system concludes about a
  session, and a human has to read that diff and approve it.

### Checking

```
git check-attr -a test/testdata/golden/git-operation.decisions.jsonl
    # text: set
    # eol: lf
```

and, on the working copy, `tr -cd '\r' < <file> | wc -c` must print `0`.

## Adding a case

Only for behavior nothing here already covers. A golden file is a maintenance
obligation, and one that exercises nothing new will be regenerated without being
read.

1. Add the recording under [`../replay/`](../replay/) and its envelope under
   [`../envelopes/`](../envelopes/), both named for the same stem.
2. Add the case to `cases` in [`../../golden/golden_test.go`](../../golden/golden_test.go),
   saying in `Why` what it pins.
3. Run `make golden`, then **read** the generated stream and write the
   per-event expectations in `expectations_test.go`. The expectations are what a
   reviewer checks; the bytes are what the machine checks.
