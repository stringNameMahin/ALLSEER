# Envelope fixtures

Committed Expected Capability Envelopes, one per replay recording it governs.

| File | Session | Governs |
|---|---|---|
| `git-operation.json` | `s-git` | [`../replay/git-operation.jsonl`](../replay/git-operation.jsonl) |
| `credential-egress.json` | `s-exfil` | [`../replay/credential-egress.jsonl`](../replay/credential-egress.jsonl) |

Until these existed, every envelope in the tree was built in Go inside a test.
That was workable for unit tests and blocking for two things: `allseerctl policy
dry-run`'s `--envelope` flag had nothing to point at, and the end-to-end golden
test would have had to construct half its own input in code — which is the
failure mode where a fixture quietly becomes an argument for the behavior it is
supposed to be testing.

## How they were written

**As an honest envelope for the stated task, without reference to what the
recording contains.** That rule matters more than anything else about these
files. `credential-egress.json` grants the workspace, the interpreter the task
runs, and the one registry it is expected to reach. The credential read in that
recording is a departure precisely because an envelope written for
"install the dependencies and build" does not anticipate it. An envelope
back-fitted to the recording would make the corpus prove that the system finds
what it was told to find.

`git-operation.json` is the one shape that could not be written naively: a
workspace-wide `fs.write` grant would swallow `.github/workflows/`, so the
envelope carries an explicit denial carving it back out. That is a real
authoring pattern rather than a test construction — a broad grant plus a
narrower denial is how any envelope covering a repository has to be written,
and denials winning over grants is what makes it safe.

Each grant carries a `rationale`, as a sealed envelope should: the field is what
a human reads when asked to approve one, and an envelope full of unexplained
capabilities is one that gets approved without being read.

## Constraints

Both set only `workspace_root`. Budget constraints (`max_file_writes`,
`max_processes`, `max_network_bytes`, `max_duration`) are deliberately left
unset: with them, a golden decision stream would encode how much budget each
recording happens to consume, and any edit to a recording would move verdicts in
a way that looks like a regression in the validator. The constraint machinery has
its own tests in [`internal/validator`](../../../internal/validator/) and
[`internal/session`](../../../internal/session/).

## Admission

Both pass `validator.LintEnvelope` with no blocking issue, asserted by
`TestGoldenEnvelopesAreAdmissible`. Non-blocking findings are logged rather than
failed: a linter that refused every judgment call would be one operators route
around, and a realistically broad envelope is expected to draw some.

## Format

`pkg/ece.Envelope` as JSON, matching
[`api/schema/ece.v1alpha1.schema.json`](../../../api/schema/ece.v1alpha1.schema.json).
The `$comment` key is a documentation field the schema's own example also uses;
loaders tolerate unknown fields, because an envelope may have been written by a
newer build.

`sealed: true` on both. An unsealed envelope is a draft, and governing a session
with one would mean governing against something still being edited.
