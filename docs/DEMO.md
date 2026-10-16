# PenX demo: authorized target to local report

> **Documentation demonstration — not a recording.** The diagram and CLI transcript below illustrate the current workflow. The optional HTML/PDF generator uses **synthetic data** only and never performs scans, DNS lookups, or model requests.

![PenX illustrated workflow](../assets/penx-demo-flow.svg)

## Five steps

1. [Install from source](../README.md#quick-start). After verified Windows binaries are published, they will be linked from [GitLab Releases](https://gitlab.com/SLP-DEV1/PenX/-/releases).
2. Keep the **entire extracted portable folder** intact and start **PenX.exe**. At first launch the scanner wizard asks before installing missing third-party components. Scanner binaries and an LLM are not bundled.
3. If using AI analysis, start your own local Ollama, LM Studio or llama.cpp server and complete the guided LLM setup.
4. Choose **[1] New Scan**, supply an IP/domain you own or are expressly authorized to assess, then select the scanners. **0** in the tool picker means Passive-Only Recon, **a** selects tools 1–5, **n** adds Nikto, and **x** selects all 12 tools (with active-scan confirmation). Passive providers receive lookup queries.
5. Review the evidence and tentative AI findings. Completed saved assessments automatically produce HTML/PDF reports in the **reports/** directory. Use **[2] View History** to inspect, regenerate or delete them.

## Illustrated terminal excerpt

The following is a documentation excerpt, not a screenshot of a finished scan:

    PenX | AI Security Assessment | Local LLM | Windows 10/11
    [1] New Scan
    [2] View History
    [9] Scan Diff & Trends
    [12] Local AI Setup / Reconfigure
    penx> 1
    [?] Enter target IP or domain: example.test
    [0] Passive-Only Recon
    [1] Nmap
    [2] WHOIS
    [3] WhatWeb
    [4] HTTP headers
    [5] DNS
    [6] Nikto
    [a] Standard Scan (1-5)
    [n] Standard Scan + Nikto (1-6)
    [x] Full Scan (12 tools, confirmation)
    [Esc] Back

**example.test** is a documentation-only domain, not a live target.

## Generate a sample report without scanning

Once the Python dependencies are installed, run from the repository root:

    python scripts/generate_demo_report.py

Open the generated **demo_output/penx_SL1_example_test.html** and **demo_output/penx_SL1_example_test.pdf** files. The generator calls PenX's actual HTML/PDF export functions using invented, non-sensitive in-memory rows. The default folder is gitignored. There is **no live target, no confirmed vulnerability, no AI result and no network request**. The sample is for demonstrating *report format*, not detection accuracy.

For an authentic animated demo, record an authorized local lab and scrub all IPs, internal names, API keys, customers and usernames. Show the real tool/menu, a genuine scan, the actual local LLM output, and opening the HTML/PDF reports. This launch kit deliberately does **not** present illustrative artwork as a real capture.

Further reading: [Scanning and reports](SCANNING_AND_REPORTS.md) · [Local AI setup](LOCAL_AI_AND_CVE.md).
