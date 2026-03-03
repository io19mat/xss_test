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
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)

func fetchRenderedHTML(target string, timeout time.Duration, wait time.Duration) (string, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	ctx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	var html string
	err := chromedp.Run(ctx,
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
	target := flag.String("url", "", "Target URL to scan")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	renderJS := flag.Bool("js", false, "Render JavaScript with headless browser before form scanning")
	renderWaitMs := flag.Int("js-wait", 1500, "Wait time in milliseconds after page load when -js is enabled")
	testServer := flag.Bool("testserver", false, "Start a local vulnerable test server")
	flag.Parse()

	if *testServer {
		go startTestServer()
		time.Sleep(1 * time.Second) // Give server time to start
		*target = "http://localhost:8080"
	}

	if *target == "" {
		fmt.Println("Usage: go run main.go -url=https://example.com")
		fmt.Println("Or: go run . -testserver")
		os.Exit(1)
	}

	// Set up HTTP client
	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	fmt.Printf("Scanning target: %s\n", *target)

	// Example: Make a GET request to the target
	resp, err := client.Get(*target)
	if err != nil {
		fmt.Printf("Error connecting to target: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("Received HTTP %d from %s\n", resp.StatusCode, *target)

	// XSS Check: inject payload into query param and check reflection
	xssPayload := "<script>alert('xss')</script>"
	parsedUrl, err := url.Parse(*target)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		os.Exit(1)
	}

	// Add or replace a query parameter for XSS testing
	q := parsedUrl.Query()
	testParam := "xss_test"
	q.Set(testParam, xssPayload)
	parsedUrl.RawQuery = q.Encode()

	fmt.Printf("Testing for reflected XSS with payload: %s\n", xssPayload)
	resp, err = client.Get(parsedUrl.String())
	if err != nil {
		fmt.Printf("Error during XSS test: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	// Check if the payload is reflected in the response, using local Go server for testing
	fmt.Printf("Response body length: %d\n", len(body))
	fmt.Printf("Looking for payload: %s\n", xssPayload)
	fmt.Printf("Payload found: %v\n", strings.Contains(string(body), xssPayload))

	if strings.Contains(string(body), xssPayload) {
		fmt.Printf("[!] Potential reflected XSS vulnerability detected! Payload found in response.\n")
	} else {
		fmt.Printf("[+] No reflected XSS detected with basic payload.\n")
	}

	// Form-based XSS check
	fmt.Println("\nScanning forms for XSS...")
	htmlForFormScan := string(body)
	if *renderJS {
		waitDuration := time.Duration(*renderWaitMs) * time.Millisecond
		fmt.Printf("JavaScript rendering enabled; loading page in headless browser (wait=%s)...\n", waitDuration)
		renderedHTML, renderErr := fetchRenderedHTML(*target, time.Duration(*timeout)*time.Second, waitDuration)
		if renderErr != nil {
			fmt.Printf("Warning: could not render JavaScript page (%v). Falling back to raw HTML response.\n", renderErr)
		} else {
			htmlForFormScan = renderedHTML
			fmt.Printf("Rendered DOM length: %d\n", len(htmlForFormScan))
		}
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlForFormScan))
	if err != nil {
		fmt.Printf("Error parsing HTML for forms: %v\n", err)
		return
	}

	foundForm := false
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		foundForm = true
		action, exists := s.Attr("action")
		method, _ := s.Attr("method")
		if !exists || action == "" {
			action = *target
		} else if !strings.HasPrefix(action, "http") {
			base, _ := url.Parse(*target)
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

		fmt.Printf("Testing form %d at %s with method %s\n", i+1, action, method)
		var formResp *http.Response
		if method == "POST" {
			formResp, err = client.Post(action, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
		} else {
			formURL, _ := url.Parse(action)
			formURL.RawQuery = formData.Encode()
			formResp, err = client.Get(formURL.String())
		}
		if err != nil {
			fmt.Printf("Error submitting form: %v\n", err)
			return
		}
		defer formResp.Body.Close()
		formBody, err := io.ReadAll(formResp.Body)
		if err != nil {
			fmt.Printf("Error reading form response: %v\n", err)
			return
		}
		if strings.Contains(string(formBody), xssPayload) {
			fmt.Printf("[!] Potential reflected XSS in form %d at %s!\n", i+1, action)
		} else {
			fmt.Printf("[+] No reflected XSS detected in form %d.\n", i+1)
		}
	})
	if !foundForm {
		fmt.Println("No forms found on the page.")
	}
}
