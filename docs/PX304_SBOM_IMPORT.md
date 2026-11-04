# PX-304 — Local SBOM package inventory (first safe slice)

**Status:** partial source implementation, not vulnerability matching or release acceptance.

This feature inspects explicitly supplied local JSON files. It uses no
network, remote scanner, LLM, advisory provider, package manager, executable
or automatic cloud upload. It does not attempt to infer affected versions
from package names, CVEs, version strings or banners.

## Commands

~~~powershell
python penx.py sbom inspect --file "C:\\PenX\\private\\inventory.cdx.json"
python penx.py sbom inspect --file "C:\\PenX\\private\\inventory.spdx.json" --show-identities
~~~

By default, report `penx-sbom-inventory-v1` includes only the source
format, total component count, verified exact package-URL identity count,
unresolved component count and supported ecosystem totals. The list of
names and exact installed versions is **omitted by default**; use
`--show-identities` only when output disclosure is authorized.

Supported formats in this first slice are **CycloneDX JSON 1.5/1.6** and
**SPDX JSON 2.3**. A bounded importer accepts only **unqualified PyPI and
npm package URLs (purl)** with exact unambiguous versions and basic syntax.
Other ecosystems, missing package URLs, version mismatches, qualifiers,
subpaths and unsupported selectors are counted as **unresolved**, never
silently matched to an unrelated package. Equivalent PyPI spelling/case is
normalized by its package URL. Duplicate exact identities, multiple SPDX
purls for one component, invalid percent escapes, malformed JSON keys and
invalid label types fail closed.

This is a deliberate **inventory-only** step: it does not query OSV/NVD,
infer affected ranges, evaluate vendor backports, or claim a package is
patched or exploitable. `status=inventory-only-no-advisory-check` and
`vulnerability_verified=false` are always returned. An empty inventory
or no exact package URLs must never be interpreted as "no vulnerabilities."

## Input limits / security

The file must be an existing regular, non-symlink path, opened once with
an inode check and read bounded to **2 MiB**. Maximum 2,000 components and
20 SPDX external references per package. Duplicate JSON object keys,
invalid UTF-8 and non-JSON numeric constants are refused. Internal malformed
content cannot be echoed in CLI errors; exceptions return a generic
`sbom-inventory-check-failed` status. No local databases or exports are
modified.

Synthetic tests cover both formats, ambiguous upstream and vendor package
identities, duplicate entries and JSON fields, version and URL confusion,
Unicode/control input, limits, symlinks, redaction, CLI dispatch and no
network/process invocation.

## Remaining PX-304 acceptance

A future separately reviewed implementation must add reliable exact
ecosystem/version/advisory matching, vendor/backport applicability, full
CycloneDX/SPDX variants, and real operator field acceptance. This partial
importer must **not** be treated as a vulnerability exposure scanner.
