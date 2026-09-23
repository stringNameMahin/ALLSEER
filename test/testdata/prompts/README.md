# Labeled prompt corpus

`corpus.json` is the expectation table for `intent.RuleAnalyzer`. It is
hand-written, not captured: every case exists because it pins one decision the
analyzer has to get right, and the labels are what a careful reader says the
prompt means rather than what the current code happens to produce.

It is loaded by `internal/intent/rules_test.go`, which runs every case through
`RuleAnalyzer.Analyze` and `RuleClassifier.Classify`.

The corpus is the baseline an LLM analyzer has to beat. That is its purpose:
without a fixed set of prompts and agreed answers there is no way to tell
whether an analyzer change helped, and "the envelope looked reasonable" is not a
measurement.

## Format

One JSON document. `cases` holds the table.

| Field | Meaning |
|---|---|
| `name` | Unique case name, used as the subtest name |
| `prompt` | The request verbatim, exactly as a user would type it |
| `prior_turns` | Preceding conversation, when the case tests multi-turn handling |
| `workspace` | The structural metadata the shim would gather. Never file contents |
| `expect` | The labeled analysis |

`expect` names only the fields a generator or a human approver actually reads:
`task_type`, `confidence`, `requires_network`, `destructive`, `workspace_only`,
the distinct `verbs` the actions carry, the three scope hint lists, and the
`ambiguities` verbatim.

`verbs` is a sorted set rather than a sequence, because the corpus labels which
operations a task implies, not the order the analyzer happens to emit them in.

## Rules for adding a case

1. Write the label first, from the prompt alone. A label edited afterwards to
   match the output measures nothing.
2. When the analyzer disagrees with a label, one of the two is a defect. Decide
   which before changing either.
3. `confidence` is asserted exactly. The analyzer rounds to two decimals so this
   stays comparable between runs.
4. An analyzer that cannot resolve something must say so in `ambiguities`. A
   case whose honest answer is "unclear" is as valuable as one with a clean
   reading, and `unknown` is a real task type here rather than a failure.
