# Local browser preview (PX-301 first slice)

**Status: opt-in browser-assisted DOM discovery on an explicitly authorized
loopback test application only. NOT an active web vulnerability scanner,
authenticated crawler, exploit validator or production-web scanner.**

The preview can render simple JavaScript applications using an optional
Playwright/Chromium installation and list bounded same-origin paths plus
HTML form methods/actions. It does **not** submit forms, fill inputs, copy
cookies/response bodies, store HTML, run an LLM, or assert missing security
findings. It cannot connect to named Internet or LAN targets; only explicit
`localhost`, `127.0.0.1`, or `[::1]` literal URLs are accepted.

## Optional local setup

Playwright is **not bundled** or silently installed in PenX runtime or
release artifacts. To experiment with your own disposable local fixture:

```powershell
python -m pip install playwright
python -m playwright install chromium
python penx.py browser-preview --url http://127.0.0.1:8088/ --authorized --consent --max-pages 3 --output-dir ./reports
```

Alternatively, if Playwright is available and Chrome is already installed,
pass `--channel chrome`; this launches a separate isolated browser, not your
existing user Chrome profile. Only use an endpoint that you explicitly own
and control. **Do not target a production app or your live shops.**

The report `penx_browser_preview*.json` is published to a new filename,
never overwriting an earlier result. It records bounded paths, link paths,
form methods and action paths, navigation counts, blocked request counts,
failures, hashed target origin, and the following conservative status:
- `COMPLETE`: bounded DOM collection finished for selected paths and pages;
  **not** vulnerability coverage.
- `PARTIAL`: blocked outbound/unsafe requests, page failure, budget
  exhaustion, truncated link/form DOM inventories, or unvisited queued paths.
  This is not a clean result.
- `vulnerability_verified: false`, `vulnerability_scanning_performed: false`
  and `state: collected-not-assessed` are always retained.

## Explicit scope and controls

- Requires `--authorized --consent`, even for a local lab.
- Same scheme, **literal loopback IP**, port and starting path prefix for
  every browser request and queued link. Cross-origin redirects and
  non-GET/HEAD requests are aborted. Query-bearing links are never queued.
- Fresh nonpersistent context, with downloads, service workers, permissions
  and insecure TLS overrides disabled. Common WebSocket, EventSource,
  WebRTC and beacon JS APIs are blocked by an initialization script.
- No login/session import or manual browser profile takeover. Maximum 5
  page navigations, 60 link observations/page, 20 form observations/page,
  per-navigation timeout 2–20s, aggregate budget 10–120s.
- No implicit expansion from browser output to other PenX scanner adapters.
  No scheduled jobs, automatic resumption or project scope promotion.

**Safety limitations:** Browser JavaScript can issue same-origin GET requests
whose server-side behavior cannot be proven harmless. Browser-level browser
services and every possible browser/network API are not independently
attested by this slice. Use a disposable local test fixture only. The result
records DOM structure, not a security verdict. Playwright version/channel,
Chromium installation, Windows/Kali browser field execution and any later
auth/navigation instrumentation need separate validation. External targets
require a future explicitly reviewed scope/consent design, not a flag change.

### Development checks

```powershell
python -m unittest tests.test_browser_preview -v
python offline_tests.py
python scripts/validate_distributions.py
```

Fixtures use a fully fake browser transport so CI never loads external
webpages, scans a public host or downloads Chromium. Optional independent
local browser smoke testing is tracked separately.
