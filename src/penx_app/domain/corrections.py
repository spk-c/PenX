"""Canonical correction status labels used across application layers."""

STATUS_LABELS = {
    "hallucination": "HALLUCINATION (fabricated finding)",
    "corrected":     "WRONG DETAIL (finding existed but details were wrong)",
    "downgraded":    "OVER-SEVERITY (severity was inflated without evidence)",
    "reclassified":  "MISCLASSIFIED (not a vulnerability, reclassified)",
    "verified":      "VERIFIED CORRECT",
}
