# Issue #13 – model and terminal dependency inventory

Status: **incremental implementation; not field-signed-off**.

## Boundaries already present

- \`application/assessment_service.py\` reserves, analyzes, saves and exports
  through \`AssessmentPorts\`; it has no direct input/print/model HTTP dependency.
- \`application/scanner_selection.py\` resolves scanner choices without I/O.
  \`cli/scanner_menu.py\` owns prompts and consent; scanner execution receives
  a scan-local cancellation event and will not save a cancelled assessment.
- \`analysis/analysis_pipeline.py\` routes research, model, verification and
  review through \`AnalysisPorts\`, preserving passive-only and structured
  \`auto\`/\`strict\`/\`off\` behavior.
- \`intelligence/cve_engine.py\`, \`source_verification.py\` and most
  source-research functions already accept per-call HTTP or provider ports.

## This change

\`analysis/llm_client.complete_chat\` now accepts optional \`http_post\`
and \`model_list\` ports on each request. Production callers still use
OpenAI-compatible HTTP(S) requests to llama.cpp, LM Studio or Ollama with
the same token limits, temperature, headers and timeouts. Non-stream
responses always close their connection; streaming responses keep their
context-manager cleanup path.

Empty answers, unfinished completions, premature SSE termination, malformed
SSE frames and provider \`event: error\` never become a returned completed
assessment. Invalid JSON envelope diagnostics do not echo raw provider data.
Deterministic no-network tests verify injected transports, auth/timeout
arguments, transport errors and both completion modes.

## Remaining exceptions / owner acceptance

- \`analysis/llm.py\` retains terminal progress rendering and retry policy
  adjacent to orchestration; split user-visible notifications and model retry
  policy into separately testable service/CLI ports before marking Pk08/Pk09
  fully resolved.
- \`intelligence/search.py\` now supports an optional call-local `emit` port
  for search progress without terminal I/O; its standalone demo remains a
  direct interactive \`__main__\` CLI. Production callers retain historical terminal progress by default.
- \`intelligence/source_verification.py\` has module-level NVD and KEV caches
  on the production path; injected HTTP clients already bypass these caches.
  Audit cache lifetime before changing the production client contract.
- Real llama.cpp/Ollama/LM Studio versions, 401/403, network disconnects,
  intentional user cancellation and the Windows terminal UI need independent
  field evidence. Existing \`tests/test_analysis_mode_contracts.py\` covers
  mode fallback and passive-only dispatch with mocked ports; CI success is
  not field acceptance.

Related: GitHub issue #13 and \`docs/REFACTOR_ACCEPTANCE.md\`.
