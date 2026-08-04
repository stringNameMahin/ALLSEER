# Replay fixtures

Recorded event streams in the replay format, consumed by
[`internal/telemetry/replay`](../../../internal/telemetry/replay/). Each streams
through `event.Source` exactly as a live eBPF collector would, which is what
lets the validator, risk engine, and policy engine be developed and tested on
any platform, without root and without a kernel.

The format is documented in the package doc of
[`replay.go`](../../../internal/telemetry/replay/replay.go). In short: one
JSON-encoded `pkg/event.Event` per line, with blank lines and `//` comments
allowed so a hand-written fixture can explain itself.

## The fixtures

| File | Session | Events | What it is for |
|---|---|---|---|
| `go-build.jsonl` | `s-gobuild` | 13 | Benign baseline. Clean capture, no loss. |
| `npm-install.jsonl` | `s-npm` | 10 | Network and hostname correlation. Contains real ring buffer loss. |
| `git-operation.jsonl` | `s-git` | 10 | Denial-over-grant precedence, and a failed syscall. |

### `go-build.jsonl`

A `go build ./...` of a small module. Everything in it is what an honest build
does, so a well-formed `go-build` envelope should return `within_envelope`
throughout, except two events that are legitimate *and* outside a naively
written workspace grant:

- **`gb-004`** reads `/usr/local/go/src/fmt/print.go`. Toolchain sources live
  outside the workspace. A policy that prompts here fires on every build.
- **`gb-008`** writes to `/home/dev/.cache/go-build/`. The build cache is
  outside the workspace and completely benign.

These are the false-positive shape the risk engine has to defuse without being
told to ignore the whole category. A `workspace_escape` violation is the right
verdict for both; a `request_approval` action is not.

It also spawns `compile` and `link` at `ancestry_depth: 1`, so attribution has
to follow the process tree rather than matching the root PID.

### `npm-install.jsonl`

An `npm install`, carrying the network cases.

- **`np-004`** connects to an IP the `net.dns` record at `np-003` correlates
  back to `registry.npmjs.org`. A grant naming that host matches.
- **`np-032`** connects to `151.101.1.162` with **no** correlated hostname,
  standing in for DNS-over-HTTPS and hardcoded addresses. A grant naming
  `registry.npmjs.org` must **not** match it. The safe answer is no-match
  escalating to the risk engine. If an uncorrelated connection were assumed
  equivalent, the easiest way to evade a network grant would be to skip DNS.

The stream also carries a genuine ring buffer loss: sequence jumps from 6 to 31
and record `np-031` reports `"dropped": 24`.

Both the gap and the counter survive replay verbatim. The replay source never
renumbers, because a recording that lost records must replay as a recording that
lost records. Otherwise every `fail_closed_on_drop` test built on it is
vacuous, and a truncated capture reads as a complete session.

### `git-operation.jsonl`

A `git commit -am`, exercising the carve-out shape: a profile grants `fs.write`
across the workspace and then denies `.git/` and `.github/workflows/`, because
the broad grant would otherwise swallow both.

- **`gt-006`** writes `.git/index`, expected for a commit and granted explicitly
  by a `git-operations` profile.
- **`gt-008`** writes `.github/workflows/release.yml`: supply-chain tampering
  via CI configuration, and the reason the denial exists. Denials always win
  over grants, and having one event of each kind means that precedence rule is
  exercised rather than assumed.
- **`gt-009`** is a *failed* read of `/home/dev/.ssh/id_rsa` (`ENOENT`). A
  failed syscall is still a governance signal, since an agent repeatedly failing
  to open credential material is more alarming than one that succeeds once, so
  the stream carries failures rather than only successes.

## Provenance

These three are **hand-authored**, not captured from a live kernel. Phase 2
delivers the daemon's event recorder, at which point real captures replace them
and this section should say so.

They are written to be structurally faithful. Field shapes, timestamp
monotonicity, sequence density, `ancestry_depth`, and payload selection all
match what the decoder will produce, but the specific paths, inodes, and IPs
are constructed. They are adequate for developing and testing the deterministic
core. They are **not** adequate as the evaluation corpus: the false-positive
denominator in Phase 6 needs recorded telemetry from real agents doing real
tasks, and hand-authored streams would measure the author's expectations rather
than the system's behavior.

## Adding a fixture

1. Keep `sequence` dense unless the fixture is *about* loss. If it is, make the
   gap and the `dropped` counter agree with each other and say so in a comment.
2. Keep `kernel_timestamp` monotonically increasing. The replay source delivers
   in file order and does not sort. A recording whose order disagrees with its
   timestamps is a recording bug, and hiding it here would also break the
   pipeline's per-session ordering guarantee.
3. Populate `observation`. Downstream stages read it rather than reaching into
   payload structs, which is what keeps the validator payload-agnostic.
4. Comment every event that exists to test something specific, naming what it
   tests. A fixture nobody can read is a fixture nobody will maintain.
5. Add it to `TestFixturesAreWellFormed` in the replay package, which checks
   ordering, sequence, and drop accounting for every fixture here.
