# GOScan-XSS — Concurrent Headless Reflected XSS Auditor

Purpose-built for fast, pragmatic reconnaissance of reflected XSS in web applications. GOScan-XSS combines concurrent HTTP probing with an optional headless Chromium renderer to locate and validate reflected payloads in both static and JavaScript-driven pages.

## Why this tool

- Lightweight and focused: designed for quick assessments during pentests or CI-assisted smoke checks.
- Dual-mode scanning: raw HTTP parsing for speed, and optional headless rendering for JS-heavy apps.
- Safe by default: non-destructive, uses a single, non-exploitive test payload to detect reflections.

## Prerequisites

- Go (modules-enabled)
- For JS rendering: Chrome or Chromium accessible on the host

## Install

Run dependency resolution:

```bash
go mod tidy
```

## Usage

Normal (fast) scan — no JS rendering:

```bash
go run . -url="https://example.com/sign-in"
```

Set a custom request timeout (seconds):

```bash
go run . -url="https://example.com/sign-in" -timeout=15
```

Headless Chromium (JS-rendered pages):

```bash
go run . -url="https://example.com/sign-in" -js
```

Increase post-load wait (milliseconds) when content is rendered asynchronously:

```bash
go run . -url="https://example.com/sign-in" -js -js-wait=3000
```

Local demo (built-in vulnerable test server):

```bash
go run . -testserver
```

Demo with headless rendering:

```bash
go run . -testserver -js -js-wait=2500
```

## Interpreting results

- `Received HTTP 200 ...`: target reachable and returned content.
- `[!] Potential reflected XSS vulnerability detected!`: the scanner's probe was reflected in the response body — warrants manual verification.
- `[+] No reflected XSS detected with basic payload.`: basic reflection not observed; not a guarantee of safety.
- `Testing form N at ...`: a form was discovered and submitted for testing.
- `[!] Potential reflected XSS in form N ...`: form submission produced a reflected payload — investigate further.
- `[+] No reflected XSS detected in form N.`: form did not reflect the test payload.
- `No forms found on the page.`: no `<form>` elements parsed (may be JS-only content; use `-js` for rendered DOM).

In `-js` mode:

- `JavaScript rendering enabled...`: the headless path is active.
- `Rendered DOM length: ...`: rendered DOM captured for analysis.
- `Warning: could not render JavaScript page (...)`: headless rendering failed and scanner fell back to raw HTML.

## Limitations & guidance

- This is a focused reflected XSS detector that uses a basic, non-destructive payload and simple reflection heuristics. It is intentionally conservative — use it as an initial triage tool, not a comprehensive proof-of-concept generator.
- A negative result is not definitive. Follow up with manual validation, contextual payload tuning, and a review of client-side behavior.
- If you need more aggressive testing (DOM-based XSS, stored payloads, context-aware payload generation), integrate this tool into a broader testing workflow or extend it to support additional payloads and context analysis.

## Contributing / Extending

- Add new payloads or context-aware checks to enhance coverage.
- Consider adding a CI-friendly flag to produce machine-readable output (JSON) for automated triage.

---

If you'd like, I can also:

- Add example JSON output for CI integration
- Expand the demo server with more test cases
- Add a short CONTRIBUTING section and a CLI `--format json` option

Pull requests and improvements welcome.
