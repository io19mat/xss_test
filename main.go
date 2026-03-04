package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)

func fetchRenderedHTML(parentCtx context.Context, target string, timeout time.Duration, wait time.Duration) (string, error) {
	// create a chromedp context that derives from the parent context so
	// cancellation propagates. Also apply an internal timeout for chromedp.Run.
	ctx, cancelCtx := chromedp.NewContext(parentCtx)
	defer cancelCtx()

	runCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	var html string
	err := chromedp.Run(runCtx,
		chromedp.Navigate(target),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(wait),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	if err != nil {
		return "", err
	}

	return html, nil
}

func main() {
	// Parse CLI arguments
	// `-url` accepts a single URL or a comma-separated list of URLs
	target := flag.String("url", "", "Target URL or comma-separated URLs to scan")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	renderJS := flag.Bool("js", false, "Render JavaScript with headless browser before form scanning")
	renderWaitMs := flag.Int("js-wait", 1500, "Wait time in milliseconds after page load when -js is enabled")
	workers := flag.Int("concurrency", 5, "Max concurrent scans (and chrome instances)")
	scanTimeout := flag.Int("scan-timeout", 30, "Per-target scan timeout in seconds")
	testServer := flag.Bool("testserver", false, "Start a local vulnerable test server")
	flag.Parse()

	if *testServer {
		go startTestServer()
		time.Sleep(1 * time.Second) // Give server time to start
		*target = "http://localhost:8080"
	}

	if *target == "" {
		fmt.Println("Usage: go run main.go -url=https://example.com,https://example.org")
		fmt.Println("Or: go run . -testserver")
		os.Exit(1)
	}

	// Set up HTTP client
	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	// Support multiple comma-separated targets
	targets := []string{}
	for _, t := range strings.Split(*target, ",") {
		tt := strings.TrimSpace(t)
		if tt != "" {
			targets = append(targets, tt)
		}
	}

	// Channel to collect results from workers
	results := make(chan string, len(targets))

	// jobs channel and worker pool
	jobs := make(chan string)
	var wg sync.WaitGroup

	xssPayload := "<script>alert('xss')</script>"

	// start worker goroutines
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for u := range jobs {
				// per-target context enforcing scan timeout
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*scanTimeout)*time.Second)
				res := scanTarget(ctx, u, client, time.Duration(*timeout)*time.Second, *renderJS, time.Duration(*renderWaitMs)*time.Millisecond, xssPayload)
				cancel()
				results <- res
			}
		}(i)
	}

	// enqueue jobs
	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()

	// wait for workers to finish then close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Print results as they arrive (keeps each target's output grouped)
	for r := range results {
		fmt.Println(r)
	}
}

// scanTarget performs the same checks as before but returns a grouped string
// It accepts a context so operations can be canceled on timeout.
func scanTarget(ctx context.Context, target string, client *http.Client, timeout time.Duration, renderJS bool, renderWait time.Duration, xssPayload string) string {
	var b strings.Builder
	fmtF := func(format string, a ...interface{}) { fmt.Fprintf(&b, format, a...) }

	fmtF("Scanning target: %s\n", target)
	// Use context-aware requests so they cancel when ctx is done
	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	resp, err := client.Do(req)
	if err != nil {
		fmtF("Error connecting to target: %v\n", err)
		return b.String()
	}
	defer resp.Body.Close()
	fmtF("Received HTTP %d from %s\n", resp.StatusCode, target)

	parsedUrl, err := url.Parse(target)
	if err != nil {
		fmtF("Invalid URL: %v\n", err)
		return b.String()
	}

	q := parsedUrl.Query()
	testParam := "xss_test"
	q.Set(testParam, xssPayload)
	parsedUrl.RawQuery = q.Encode()

	fmtF("Testing for reflected XSS with payload: %s\n", xssPayload)
	testReq, _ := http.NewRequestWithContext(ctx, "GET", parsedUrl.String(), nil)
	testResp, err := client.Do(testReq)
	if err != nil {
		fmtF("Error during XSS test: %v\n", err)
		return b.String()
	}
	defer testResp.Body.Close()

	body, err := io.ReadAll(testResp.Body)
	if err != nil {
		fmtF("Error reading response body: %v\n", err)
		return b.String()
	}

	fmtF("Response body length: %d\n", len(body))
	fmtF("Looking for payload: %s\n", xssPayload)
	found := strings.Contains(string(body), xssPayload)
	fmtF("Payload found: %v\n", found)
	if found {
		fmtF("[!] Potential reflected XSS vulnerability detected! Payload found in response.\n")
	} else {
		fmtF("[+] No reflected XSS detected with basic payload.\n")
	}

	// Form scanning
	fmtF("\nScanning forms for XSS...\n")
	htmlForFormScan := string(body)
	if renderJS {
		fmtF("JavaScript rendering enabled; loading page in headless browser (wait=%s)...\n", renderWait)
		renderedHTML, renderErr := fetchRenderedHTML(ctx, target, timeout, renderWait)
		if renderErr != nil {
			fmtF("Warning: could not render JavaScript page (%v). Falling back to raw HTML response.\n", renderErr)
		} else {
			htmlForFormScan = renderedHTML
			fmtF("Rendered DOM length: %d\n", len(htmlForFormScan))
		}
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlForFormScan))
	if err != nil {
		fmtF("Error parsing HTML for forms: %v\n", err)
		return b.String()
	}

	foundForm := false
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		foundForm = true
		action, exists := s.Attr("action")
		method, _ := s.Attr("method")
		if !exists || action == "" {
			action = target
		} else if !strings.HasPrefix(action, "http") {
			base, _ := url.Parse(target)
			rel, _ := url.Parse(action)
			action = base.ResolveReference(rel).String()
		}
		method = strings.ToUpper(method)
		if method == "" {
			method = "GET"
		}

		formData := url.Values{}
		s.Find("input").Each(func(j int, input *goquery.Selection) {
			name, exists := input.Attr("name")
			if exists && name != "" {
				formData.Set(name, xssPayload)
			}
		})

		fmtF("Testing form %d at %s with method %s\n", i+1, action, method)
		var formResp *http.Response
		if method == "POST" {
			postReq, _ := http.NewRequestWithContext(ctx, "POST", action, strings.NewReader(formData.Encode()))
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			formResp, err = client.Do(postReq)
		} else {
			formURL, _ := url.Parse(action)
			formURL.RawQuery = formData.Encode()
			getReq, _ := http.NewRequestWithContext(ctx, "GET", formURL.String(), nil)
			formResp, err = client.Do(getReq)
		}
		if err != nil {
			fmtF("Error submitting form: %v\n", err)
			return
		}
		defer formResp.Body.Close()
		formBody, err := io.ReadAll(formResp.Body)
		if err != nil {
			fmtF("Error reading form response: %v\n", err)
			return
		}
		if strings.Contains(string(formBody), xssPayload) {
			fmtF("[!] Potential reflected XSS in form %d at %s!\n", i+1, action)
		} else {
			fmtF("[+] No reflected XSS detected in form %d.\n", i+1)
		}
	})
	if !foundForm {
		fmtF("No forms found on the page.\n")
	}

	return b.String()
}
