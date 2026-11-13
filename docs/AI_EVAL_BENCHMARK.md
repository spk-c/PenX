# PX-403: reproducible offline AI finding benchmark (fixture slice)

This tool is an **offline, labelled synthetic benchmark**, not proof that an
actual LLM or a vulnerability scanner is accurate. It never sends requests,
starts a model, contacts a scan target, modifies a user database, uploads data,
or automatically downloads any model. Results from the shipped example are
**not measured Qwen/NInfer/Strata performance**.

## Run

```bash
python scripts/benchmark_ai_assessment.py
python scripts/benchmark_ai_assessment.py \
  --corpus tests/fixtures/ai_eval_corpus_v1.json \
  --predictions tests/fixtures/ai_eval_predictions_v1.json \
  --output ./ai-eval-local-report.json
```

All inputs are explicit local JSON files (up to 1 MiB each). `--output`
writes a **new** JSON report; it will not overwrite an existing file.
Without `--output`, the sanitized report is printed to stdout.
The exit status is `0` for a valid score (even if the predictions are poor),
`2` for invalid/unreadable inputs or an output error. An invalid input never
produces a successful benchmark report.

## Versioned contract

The corpus declares `schema: "penx-ai-eval-corpus-v1"`,
`prompt_sha256` (64 lowercase hex digits), and `cases` (1 to 100).
Each case has a unique `id`, a bounded `evidence` string, and up to 64
`expected` findings. Every expected finding has `id`, boolean
`supported`, and `quote`. Supported findings must cite an **exact,
nonempty substring** of their own case's evidence; unsupported entries
must have `quote: null`. The expected set can include intentionally
fabricated CVE claims, missing headers, incomplete TLS trust information,
and other known negatives.

The predictions declare
`schema: "penx-ai-eval-predictions-v1"`, the same `prompt_sha256`,
and the exact same case IDs. Every case includes `status` and
`findings` (each with `id` and `quote`).
Status is `complete`, `refusal`, `timeout`, or `invalid_json`.
Any noncomplete case must have an empty findings list and is counted as
incomplete, **never as a clean security result**. Wrong-quote, duplicate
ID, foreign-case, missing-case and unknown-schema inputs fail closed
where structural, or count as unsupported predictions where factual.

Each exact supported rubric anchor emitted with the matching quote is a
true-positive **fixture anchor**. Unsupported/unknown finding IDs and
wrong-quote claims are counted as false positives; omitted or wrong-quote
supported anchors are false negatives. Precision and recall are ordinary
ratios of those counts, `null` where the denominator is zero.
The benchmark uses **exact string matching**, not semantic entailment,
vendor patch applicability, exploit validation or expert confirmation.

## Reproducibility and privacy

Both entire input files are SHA-256 hashed into the machine-readable report
along with the versioned schema and aggregate counts. The prompt SHA-256
must match between the two inputs. The report intentionally excludes raw
prompts, targets, quotes, evidence, finding IDs and model responses.
Use **synthetic or independently sanitized** inputs only; source files
remain sensitive if a real user supplies raw scanner or model output.

The shipped fixtures exercise supported observations, unsupported invented
RCE/TLS assertions, refusal and timeout. Their aggregate sample metrics
are diagnostic *fixture examples*, **not a measured AI quality baseline**.
Operators may separately generate local predictions and score those offline,
but a self-reported prediction file does not prove which model ran it.
The offline scorer above never calls a model or network endpoint. The opt-in
local runner below is a separate command; it does not change that contract.

## Opt-in local model-output benchmark (PX-403 first live slice)

The **separate** `scripts/benchmark_local_ai.py` runner asks an explicitly
configured **loopback-only** OpenAI-compatible endpoint to classify labelled
synthetic observations. It reuses the offline scorer above, but sends the
model **only** candidate IDs and synthetic evidence. The rubric's support
flags and expected-quote *fields* are not sent; the original observed text
necessarily contains the quoted substrings for positive cases. The original offline
`benchmark_ai_assessment.py` remains completely network-free.

```powershell
python scripts/benchmark_local_ai.py --endpoint http://127.0.0.1:8080 --model qwen3.8-27b --output ./local-ai-metrics.json
```

Replace the model ID with the *actual* configured local server ID. This
command is **opt-in**, requires an already running compatible server, does
not start NInfer/Strata/Ollama, and does not scan any target or fetch CVEs.
It does not use a proxy, follow redirects, accept a remote endpoint, or
enable any scan permissions. The server must support strict JSON-Schema
chat completions; unsupported formats yield explicit incomplete cases
rather than silently using unconstrained prose.

The runner limits each corpus to **20** synthetic cases, each request to
**5–120 seconds**, and the aggregate batch to **at most 600 seconds**.
The model cannot invoke PenX scanners, arbitrary tools or shell commands.
Duplicate/invalid JSON, refusal and timeout are tracked as incomplete
cases, not clean findings. Well-formed unsupported IDs and invented quotes
remain **false positives** in the scoring denominator, not discarded.
Transport failures fail the run without inventing a score.

Printed output (or the new, exclusive `--output` file) contains only
aggregate counts, hashed model ID and prompt/corpus digests. It omits
the evidence, labels, quotes and model responses. The recorded fact is
**local API completion observed**; the endpoint does not cryptographically
prove which model is loaded. For that reason `model_identity_verified`
and `real_model_executed` remain false until a separate provider-identity
gate is implemented. Even perfect fixture precision is **not** proof of
real-world vulnerability detection, or authorization to scan external hosts.

The fixture set is currently small and synthetic, not an independent
industry benchmark. Run this only with approved synthetic/sanitized inputs,
and do not publish private results or model server credentials.

## Remaining PX-403 acceptance

- A separately approved, authentic **loaded-model** identity/provenance check,
  end-to-end cancellation and more provider compatibility tests. The initial
  bounded loopback runner covers request budgets, refusal and malformed JSON.
- Curated larger human-reviewed benchmark for claim accuracy and recall,
  independent dataset provenance and prompt/version governance.
- Side-by-side NInfer/Strata/llama.cpp/Ollama operator validation, with
  verifiable loaded-model provenance and reproducibility details.
- Independent review of benchmark false positives, redaction and metrics;
  synthetic CI cannot stand in for field-model accuracy.

This slice is deliberately separate from runtime assessment generation and
never promotes a scanner observation or model claim to a verified finding.
