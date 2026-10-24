
# Changelog

## 2.1
- Added persistent todo items with dependency-aware readiness.
- Added deduplicated finding IDs and a prioritized report summary.
- Added operator hints (`--hint`) to steer planning between runs.
- Added planner registry dispatch for all declared test IDs.
- Added configurable provider base URLs for compatible gateways.
- Expanded automated tests for todos and finding deduplication.
- Kept scope/method enforcement outside the LLM so model output cannot directly issue arbitrary requests.

## 2.1.1
- Rebranded the application as ARTEMIS (Autonomous Application Security Testing Platform).
- Added the `artemis.py` CLI entry point and `--version` flag.
- Updated the primary documentation and command examples to use ARTEMIS.
- Retained `agent.py` as a backwards-compatible entry point.

## 2.2.0
- Upgraded the persistent blackboard schema with backward-compatible migration defaults, atomic writes and fail-closed corrupt-state handling.
- Added first-class claim lifecycle records with provenance, evidence references, explicit verification states and review history.
- Added in-run asset records, structured trace retrieval, graph integrity checks and stricter todo dependency/status validation.
- Integrated baseline/test/planner traces and `pending_verification` claims into the assessment engine.
- Fixed path-prefix boundary matching so `/api` does not authorize `/apix`.
- Added `--validate-state` and initial architecture, parity, threat-model, roadmap and benchmark documentation.
- Added per-test execution status history so deferred or blocked tests are not counted as completed coverage.
- Reports now expose unresolved claim states and per-test coverage gaps rather than implying missing configuration was tested.
- Added integration coverage for end-to-end offline execution, deferred OpenAPI inventory, and report claim lifecycle.


## 2.2.1
- Redacted common secret-bearing fields in captured request/response headers, URLs, structured JSON bodies, and model-safe observations.
- Preserved the SHA-256 of the original response body while storing a redacted representation; binary response bodies are omitted from persisted body content.
- Hardened evidence writes against filename traversal and symlink destinations, and enforce restrictive file permissions plus fsync.
- Tightened policy and URL validation for malformed ports, URL fragments, control characters, backslashes, ambiguous host allowlists, and malformed method/path configuration.
- Bound HTTP(S) socket connections to a freshly resolved and policy-checked IP address while retaining the original hostname for HTTP Host and TLS certificate/SNI validation; proxy routing is rejected because it bypasses this guarantee.
- Added a DNS-rebinding regression test that changes a host from a public IP at preflight to a private IP at connection time and confirms the request is blocked.
- Added regression tests for nested JSON secrets, query-string secrets, symlink writes, path traversal, and ambiguous URL/policy inputs.
