# Ollama report timeout diagnosis and focused fix

Date: 16 November 2026. This follow-up supplements the historical [integration audit](INTEGRATION_AUDIT_REPORT.md); its earlier timeout observations were not rewritten.

**Result:** the existing local model can generate a small forensic report on this laptop with bounded context and output. The final-code harmless-evidence run completed in **36.047 seconds**, in full `llm` mode, with normal completion, four nonempty report sections, passing citations and verified Markdown/PDF exports. This does not establish reliable full-LLM generation for large investigations or arbitrary laptop workloads.

## What was configured and available

| Item | Verified value |
|---|---|
| Dashboard-selected model | `llama3.2`, unchanged |
| Installed canonical model | `llama3.2:latest`, 3.2B parameters, GGUF, Q4_K_M |
| API-reported local model digest | `a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72` |
| Model size on disk reported by tags | 2,019,393,189 bytes |
| Service | Ollama 0.40.16; local version/tags/ps endpoints responded |
| Application endpoint | `http://localhost:11434/api/generate`, unchanged; direct diagnostics also used `127.0.0.1:11434` |
| Previous request settings | Non-streaming, temperature 0.1, up to 700 output tokens, no explicit context limit, 10-minute keep-alive |
| Previous time limits | 120-second request read timeout; nominal 180-second report budget not applied to remaining per-call time |
| Available hardware at first probe | 7.405 GiB usable physical RAM; 1.454 GiB available, 80% memory load, 12 logical CPUs |
| Observed execution | API reported zero VRAM residency; service logs selected CPU inference |

The public Python constructor retains its legacy `model_name="llama3"` default for compatibility. That model is not installed here. The dashboard explicitly passes `llama3.2`; standalone callers should also pass their selected installed model explicitly. No model is silently substituted when a selection is missing.

## Diagnosis before editing application code

Read [INTEGRATION_AUDIT_REPORT.md](INTEGRATION_AUDIT_REPORT.md) and [FYP_DEMO_GUIDE.md](FYP_DEMO_GUIDE.md), then checked availability and issued independent generation requests using the existing model.

| Probe | Elapsed | Evidence |
|---|---:|---|
| Service version/tags connectivity | About 0.06 seconds each | Reachable service and installed model; not an unavailable-service failure |
| Minimal non-streaming request, eight-token ceiling | **45.860 s** | Completed normally with `OK.`; server reported 28.571 s loading, 6.054 s prompt evaluation and 3.626 s decoding three output tokens |
| Minimal bounded stream, 2,048-token context | **10.735 s** | First token at 7.578 s; 22 output tokens; normal completion |
| Independent compact four-section prompt | **23.875 s** | 844-byte prompt, 128 output tokens; normal completion. This transport probe was not itself used as a trusted forensic export. |

The service and model were working. Loading and CPU inference consumed substantial time, and the earlier application had no explicit small context limit, allowed 700 output tokens and did not bound prompt bytes. The measured cold/loading overhead and generation work can exhaust its 120-second wait. The exact partition of the historical timed-out requests cannot be reconstructed because they did not retain server timing metrics.

On exactly the same harmless YARA finding, the application prompt decreased from **2,667 to 1,274 UTF-8 bytes**, a **52.23% reduction**. A separate synthetic 25-finding stress case produced a **1,106,739-character** original prompt: limiting finding count did not limit source-field size.

Ollama documents separate loading, prompt-evaluation and decoding timings, reported in nanoseconds. Its context documentation explains that larger contexts require more memory. These definitions informed the measurements and bounded-context change. [Generate API](https://docs.ollama.com/api/generate), [context memory guidance](https://docs.ollama.com/context-length).

## Changes

1. Added a small standard-library HTTP/NDJSON transport in [modules/ollama_client.py](modules/ollama_client.py). It distinguishes connection failure, connection timeout, unavailable model/endpoint, HTTP/server error, malformed response, generation timeout and incomplete generation. Diagnostics retain connection/first-token timing and the server's loading, prompt-evaluation and decoding metrics when available.
2. Kept the configured model and endpoint. Default request options now explicitly use **2,048 context tokens**, **320 maximum full-report tokens**, temperature **0.1**, and **one-minute model keep-alive**. Summary-only generation is capped at **128 tokens**. No global Ollama settings were changed.
3. Retained the 120-second maximum idle-read wait and 180-second report budget. The budget now uses a monotonic clock, is shared across attempts and caps connection/read waits by remaining time. Stream consumption checks the budget even while tokens continue arriving. It does not expose partial tokens as a report.
4. Removed duplicated prompt instructions while preserving citation, severity, source-only wording, YARA/ML uncertainty and UTC chronology requirements. A conservative UTF-8 byte ceiling reserves context/output space without installing a tokenizer. The default full-report ceiling is **1,472 bytes**; the summary ceiling is **1,664 bytes**. These are conservative input safeguards, not exact tokenizer counts.
5. Oversized prompts fail before contacting Ollama. Finding fields are not silently shortened. The existing deterministic reporter and its existing representative-finding/count policy remain available, with the reason clearly recorded and displayed.
6. Only streams with matching model identity, valid events, nonempty text, `done=true` and `done_reason="stop"` reach content validation. Token-limit completion (`length`), premature EOF, malformed JSON/encoding, server errors and missing completion are rejected. Full LLM reports must also contain the four required nonempty sections in order.
7. Existing citation/source/audit/export validation remains mandatory. Per-attempt diagnostics record content rejection; unsuccessful or partial responses are not accepted as the verified report. The existing explicitly labeled hybrid/template paths remain.
8. The dashboard stores generation diagnostics in newly generated report records before their integrity binding. Existing report records and histories were not rewritten. The UI layout and configured model choice are unchanged.

The transport reads only bounded response data (256 KiB maximum) and uses public socket/HTTP APIs. There are no new dependencies, model downloads, service restarts, GPU-setting changes, checkpoint replacements or training operations.

## Actual report results

Harmless bytes `AEGIS_YARA_TEST_MARKER_2026\n` were scanned with the existing YARA scanner. SHA-256: `d24ae586a7363987973ce586b193c316ebd19296b6bf0ac7cbf450b4cccfe722`. Test cases, source copies, audit chains and exported reports were created only inside the new audit-artifact directory.

| Run | Elapsed generation | Result | Citation and Markdown/PDF export checks |
|---|---:|---|---|
| Compact-prompt repeated run 1 | **35.860 s** | Full LLM report, one completed model call | PASS |
| Compact-prompt repeated run 2 | **46.406 s** | Full LLM report after an unsupported-wording response was rejected and a corrected response accepted | PASS |
| Final code, including structural checks | **36.047 s** | Full LLM report; `stop`, four nonempty sections, citations passed | PASS |

Final-code run metrics: first token **13.453 s**; connection **2.109 s**; server load **6.520 s**; prompt evaluation **4.711 s** for **327 input tokens**; decoding **22.581 s** for **169 output tokens**. The localhost connection step was measurable but did not explain the original 120-second timeout.

An earlier tuning run produced an explicitly labeled **hybrid** report after full prose failed validation. That result is preserved separately and is not counted as successful full-LLM generation. Model-generated wording is still fallible; keeping the validator and labeled fallback is necessary.

Markdown and extracted PDF text were checked for the same finding ID, source filename and SHA-256. Export binding and evidence checks passed. These follow-up generation/export tests were **backend calls**, not a new interactive Streamlit browser walkthrough.

## Automated validation and preservation

**322 tests passed**, including the existing 309 tests and 13 new Ollama reliability tests. The final runner captures Python's actual exit status independently of PowerShell's formatting of unittest output on stderr.

New tests use real temporary loopback HTTP servers. They cover complete streamed responses and metrics, continuously arriving tokens at the wall deadline, idle first-token timeout, unavailable service/model, invalid JSON/encoding/types, server errors, premature EOF, token-limit termination, empty output, missing final newline, model mismatch, HTTP connection-close behavior, oversized/expired requests, invalid configuration, rejected citations, incomplete report structure, explicit validated fallback, Markdown/PDF consistency and tampering with bound generation provenance.

Backup before editing: [backups/ollama_timeout_20261116_124956](backups/ollama_timeout_20261116_124956).

**55 protected original files** under evidence/case/report/data/training/model locations were compared by path, size and SHA-256: **zero modified, zero added and zero missing**. Training code, checkpoints and original evidence were preserved. No heavyweight packages were installed.

Modified implementation/test files:

- [modules/ai_reporter.py](modules/ai_reporter.py): bounded configuration, compact prompt, shared budget, completeness/content diagnostics.
- [modules/ollama_client.py](modules/ollama_client.py): new strict streamed transport.
- [dashboard/app.py](dashboard/app.py): attach generation diagnostics to new report metadata; no layout change.
- [tests/test_ollama_reliability.py](tests/test_ollama_reliability.py): 13 new tests.
- Documentation: this new report and the updated [FYP demo guide](FYP_DEMO_GUIDE.md).

## Reproduction, configuration and limitations

For a backend caller, use the unchanged dashboard model explicitly:

```python
reporter = LocalLLMReporter(
    model_name="llama3.2",
    num_ctx=2048, max_tokens=320, summary_tokens=128,
    timeout=120, time_budget=180, keep_alive="1m",
)
```

These constructor limits are configurable without adding UI controls. Context is restricted to 512–8,192 tokens with reserved output space; time limits must be finite and at most 600 seconds. Larger contexts should not be chosen on this 8 GB laptop without separate measurement.

Start Streamlit normally and use Investigation → Investigation report → Generate report with verified harmless evidence. Review the displayed mode and reason. The saved-evidence “Generate Forensic Report” shortcut intentionally uses deterministic reporting and is not an Ollama speed test.

Remaining limits:

- The laptop remains RAM/CPU constrained. Small reports succeeded; no broad reliability claim is made for large cases, low-memory conditions, concurrent model requests or every source format.
- Long prompts exceed the conservative low-memory profile and deliberately use the labeled deterministic path. This is not successful LLM generation, and the application does not silently increase context or swap models.
- Some completed model outputs still fail citations/wording checks. Retries, a validated hybrid summary or a labeled template are expected safe outcomes; they must not be represented as a fully LLM-authored report.
- Completion plus citation/export validation is not independent proof that every natural-language inference is true. Analyst review remains required.
- Original invalid case chains, absent reviewed embedding metadata and Security-log permissions documented in the integration audit are outside this change.

All measured artifacts, exact prompts/options, raw timing metrics, sample reports, source diff and test logs are retained under [audit_artifacts/ollama_20261116_074411](audit_artifacts/ollama_20261116_074411). Useful files include `minimal_before.json`, `minimal_bounded.json`, `prompt_comparison.json`, `final_report_results.json`, `verified_report_results.json`, `verified_reports/report_1.md`, `verified_reports/report_1.pdf`, `final_full_suite.log`, `final_full_suite_result.json` and `protected_comparison.json`.
