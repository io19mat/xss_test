# XSS Test Scanner

Small Go-based reflected XSS tester for URL query params and HTML forms.

## Prerequisites

- Go installed (project uses modules)
- For JS-rendered form scanning (`-js`): Chrome or Chromium installed locally

## Install Dependencies

```bash
go mod tidy
```

## Run: Normal Scan (no JS rendering)

Scan a target URL using plain HTTP response parsing:

```bash
go run . -url="https://example.com/sign-in"
```

Optional timeout (seconds):

```bash
go run . -url="https://example.com/sign-in" -timeout=15
```

## Run: Chrome Headless Scan (JS-rendered pages)

Use headless browser rendering to detect forms injected by JavaScript:

```bash
go run . -url="https://example.com/sign-in" -js
```

Add extra wait time after page load (milliseconds):

```bash
go run . -url="https://example.com/sign-in" -js -js-wait=3000
```

Useful when forms appear after async rendering/hydration.

## Local Demo with Built-in Test Server

Start vulnerable local server and scan it:

```bash
go run . -testserver
```

With headless JS mode:

```bash
go run . -testserver -js -js-wait=2500
```

## Expected Outcomes

After a scan, these are the main results to look for:

- `Received HTTP 200 ...` means the target was reachable.
- `[!] Potential reflected XSS vulnerability detected!` means the test payload was reflected in the response body.
- `[+] No reflected XSS detected with basic payload.` means this payload was not reflected.
- `Testing form N at ...` means at least one form was found and submitted for testing.
- `[!] Potential reflected XSS in form N ...` means a submitted form response reflected the payload.
- `[+] No reflected XSS detected in form N.` means that tested form did not reflect this payload.
- `No forms found on the page.` means no `<form>` elements were present in the parsed HTML (common on JS-heavy pages without `-js`, or if content loads after the wait window).

In `-js` mode:

- `JavaScript rendering enabled...` confirms headless rendering path is active.
- `Rendered DOM length: ...` confirms rendered HTML was captured.
- `Warning: could not render JavaScript page (...)` means headless rendering failed and scanner fell back to raw HTML.

Important: this scanner uses a basic payload and reflection checks, so a negative result is not proof the target is fully XSS-safe.

## Notes

- If `-js` mode cannot start Chrome/Chromium, scanner falls back to raw HTML response parsing.
- This tool is a basic reflected XSS checker and can miss complex client-side/server-side behaviours.
