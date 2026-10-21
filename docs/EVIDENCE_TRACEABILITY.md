# Evidence traceability and scan comparison

Findings carry a `penx-finding-v1:<sha256>` fingerprint in comparison JSON and
JSON/SARIF exports. The identity includes target, name, port and service after
Unicode NFC, case and whitespace normalization. Session IDs, dates, confidence,
severity and changing evidence wording are excluded. Renamed vulnerability
claims remain distinct; existing narrowly scoped recommendation matching is
reported separately. A matching fingerprint establishes identity, not proof.

Comparison JSON includes `scan_context` for both sessions: selected scanner IDs,
coverage, and the persisted plan summary (profile ID/version, parallelism and
global budget). Text, HTML and PDF comparisons show the same context and explicit
warnings when selections or configuration differ. Missing historical metadata
stays unknown. A missing finding never automatically becomes resolved.

## Optional raw artifacts

Set `PENX_RAW_ARTIFACT_DIR` to a private directory to retain adapter captures
during assessment saving. Unset means no extra raw artifact files are written.
Captures contain unredacted scanner data; protect the directory, avoid repository
publication, and manage retention locally. There is no automatic expiry.

Only adapters with evidence and non-failed outcomes are eligible. Each exact
UTF-8 capture is limited to 1 MiB; oversized captures are omitted rather than
truncated. At most 100 adapters can be retained per assessment. Atomic exclusive
publication preserves existing files. Newline bytes are preserved on Windows.
Metadata v3 optionally stores `raw_artifact` with the full SHA-256, byte count,
safe filename and `sha256-utf8-v1` validator reference. No database migration is
needed because this is an additive field in the existing versioned metadata.
Artifact-free metadata v1/v2/v3 serialization remains compatible.

`penx_app.storage.raw_artifacts.validate_artifact(adapter, directory)` loads at
most 1 MiB plus one byte, rejects unsafe paths/links, verifies length and hash,
and rechecks persisted evidence offsets and quotes against the loaded text.
Metadata parsing alone never revalidates an artifact. Reports label references
`stored-reference-not-revalidated`; missing captures stay unavailable. Hashes
attest integrity relative to a trusted reference, not origin, target identity,
or exploitability. Keep the metadata and capture directory under trusted control.

Machine exports include references rather than complete captures. Redaction
still masks report text only; it does not rewrite separately retained captures.
Fingerprint and artifact hashes can correlate exports and should be reviewed
before sharing even when textual target redaction is enabled.
