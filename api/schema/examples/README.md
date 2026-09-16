# Worked example documents

One document per schema shape, validated by
[`scripts/validate-schemas.sh`](../../../scripts/validate-schemas.sh).

| File | Schema | What it is |
|---|---|---|
| `ece.example.json` | `ece.v1alpha1.schema.json` | A reference envelope, hand-written |
| `event.example.json` | `event.v1alpha1.schema.json` | A recorded kernel event, lifted from the replay corpus |
| `decision.example.json` | `decision.v1alpha1.schema.json` | A scored decision, lifted from the golden corpus |
| `decision.unscored.example.json` | `decision.v1alpha1.schema.json` | The decision a failed pipeline stage produces |

These are the published shape of the wire contracts. `pkg/` is public precisely
so an external consumer can parse ALLSEER output without vendoring the system,
and a schema nobody has ever validated a document against is a contract in name
only.

## Where each one comes from

**`ece.example.json` is hand-written**, and is the only one that is. It is a
reference envelope for the prompt *"add a rate limiter to the HTTP middleware
and run the tests"*, written to illustrate the intended precision of a generated
envelope: narrow path globs, a specific executable allowlist, a proxy-only
network grant, and explicit denials carving dangerous paths out of a broad
workspace write grant. It is used as a schema fixture and is intended as a
few-shot example for the LLM analyzer in M8.

That paragraph used to live inside the file itself, as a top-level `$comment`
key. It was removed on 2026-09-16 because `ece.v1alpha1.schema.json` declares
`additionalProperties: false`, so the only example the project shipped did not
validate against the schema it was the example for. Nobody had noticed, because
`check-jsonschema` had never been installed on any host this was developed on
and the script skips silently when it is absent. The strictness is not the
defect: an envelope is a sealed, digest-covered security artifact, and an
unknown key riding into one is exactly what `additionalProperties: false` is
there to stop. So the prose moved here rather than the schema loosening.

**The other three are real output**, deliberately, so that a consumer reading
them sees what the system actually emits rather than what someone thought it
emitted:

- `event.example.json` is event `gt-008` from
  [`test/testdata/replay/git-operation.jsonl`](../../../test/testdata/replay/git-operation.jsonl)
  - the write to `.github/workflows/release.yml` that the git-operation
  envelope denies through a carve-out inside a workspace-wide write grant. It
  carries a file payload, a resolved path, and a populated observation, so it
  exercises more of the schema than a routine read would.
- `decision.example.json` is decision `d-ex-009` from
  [`test/testdata/golden/credential-egress.decisions.jsonl`](../../../test/testdata/golden/credential-egress.decisions.jsonl)
  - the credential-access-then-egress finding, eight risk factors and a full
  reasoning chain.
- `decision.unscored.example.json` is what `pipeline.IndeterminateHandler`
  produces when a stage fails: `"level": "unscored"` and an empty factor list.
  It is here because it is the shape the decision schema *rejected* until the
  wire format was settled, and a contract is worth more when its awkward case is
  written down.

## Regenerating

The three derived documents are copies. If the corpora they come from change,
re-derive rather than hand-editing, and read the diff: a change here is a change
in what the system publishes.

## Cross-file references

`decision.v1alpha1.schema.json` and `event.v1alpha1.schema.json` both `$ref`
into `ece.v1alpha1.schema.json`, for the action, grant, capability-kind and
domain vocabularies. Each schema's `$id` is
`https://allseer.dev/schema/<filename>`, which is what makes those
filename-relative refs resolve to the right document - under a resolver that
loads by `$id` and under one that loads from this directory alike.

That agreement is load-bearing and was not always there. Until 2026-09-16 the
`$id`s were directory-style (`.../schema/ece/v1alpha1.json`) while the refs were
filename-style, so a relative ref resolved to a document that does not exist and
a spec-compliant consumer could not use the schemas at all. Local tooling hid it
by resolving against the filesystem instead. If an `$id` is ever changed, change
it so it still agrees with the refs, or change both.
