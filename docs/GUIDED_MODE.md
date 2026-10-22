# Guided beginner collection

Choose **[g] Guided Scan** in the main menu, or launch directly without database
or AI setup:

```text
python penx.py guided
python penx.py guided --target example.test --output ./reports
```

The wizard accepts a single hostname or IP. URLs, explicit ports and subnets
remain available through advanced flows, where their scope needs closer review.
It shows the normalized exact target, explains four goals and recommends a
profile: first inventory, passive history, active web audit or broad assessment.
Every selected scanner receives a plain-language description, including which
checks contact the target and which query public providers.

Permission is required for the exact target. Consent-gated web profiles receive
a separate active-check question. A local preflight then shows selection,
prerequisites, expected scope and budgets without network collection. Missing
scanners require an additional explicit decision to continue with incomplete
coverage. A final start question defaults to **no**. Esc/back, declined consent
or EOF never launches a scan from the preview.

Confirmed runs use the existing headless collector and produce JSON/SARIF
reports. They do not reserve assessment sessions or call a model. The wizard
explains severity as potential impact, confidence as support for a claim, and
scanner evidence as an observation requiring independent review. Missing
findings do not establish safety or remediation. Explicit Nuclei/HTTP/TLS rules
receive severity policy; Nmap/Nikto observations remain informational and other
adapters supply coverage.

Existing advanced scan menus, presets and report flows remain available.
