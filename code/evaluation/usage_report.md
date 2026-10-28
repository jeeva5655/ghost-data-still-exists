# Token Usage and Cost Analysis (`usage_report.md`)

## 1. Final Full-Dataset Run Summary (518 Requests)

- **Execution Timestamp (UTC)**: `2026-10-25T11:03:47.637533+00:00`
- **Total Requests Processed (`deletion_requests.csv`)**: `518`
- **Wall-Clock Runtime**: `10.05 seconds`
- **Architecture**: Hybrid Deterministic Multi-Source Engine + Semantic Intent Classifier (`google/gemini-3.8-flash`)

## 2. Per-Model and Overall Token & Cost Totals

| Provider | Model Name | Model Calls | Input Tokens | Output Tokens | Total Tokens | Avg Tokens / Request | Estimated Total Cost (USD) | Estimated Cost / Request (USD) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `google` | `gemini-3.8-flash` | 518 | 118,855 | 33,670 | 152,525 | 294.4 | $0.025354 | $0.00004894 |
| **Overall Total** | **All Models** | **518** | **118,855** | **33,670** | **152,525** | **294.4** | **$0.025354** | **$0.00004894** |

## 3. Efficiency & Caching Optimizations
- **Pre-Indexed Evidence Store**: All SQL snapshots, JSON files, logs, PDFs, and images under `dataset/evidence/` are parsed once at startup and indexed in memory, avoiding redundant multimodal/file re-reads across the 518 cases.
- **Deterministic Policy & Sorting Engine**: Identity graph traversal, timestamp filtering (`<= audit_at`), `deletion_rules.csv` application, and step sorting execute deterministically in Python with zero hallucination risk.
