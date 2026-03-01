package main

import (
    "fmt"
    "net/http"
)

func startTestServer() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        input := r.URL.Query().Get("xss_test")
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, "<html><body>Input: %s</body></html>", input)
    })

    fmt.Println("Test server running on http://localhost:8080")
    http.ListenAndServe(":8080", nil)
}