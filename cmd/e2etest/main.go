// test_go_sdk_e2e.go
//
// Real end-to-end test: an actual net/http server (httptest), the actual
// Monitor.Middleware() from the SDK, a real HTTP request, a real network
// POST to a live ingest server.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	loguard "github.com/LoGuardSecurity/loguard-sdk-go/loguard"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("ERROR: pass an API key as the first argument")
		os.Exit(1)
	}
	apiKey := os.Args[1]

	mon, err := loguard.NewMonitor(loguard.InitOptions{
		APIKey:                 apiKey,
		BaseURL:                "http://localhost:8000",
		Env:                    "e2e-go-sdk-test",
		AllowInsecureTransport: true,
	})
	if err != nil {
		fmt.Println("Init error:", err)
		os.Exit(1)
	}

	handler := mon.Middleware(loguard.MiddlewareOptions{
		TrackStatuses: map[int]bool{500: true},
		TrackHeaders:  loguard.KnownExploitHeaders,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/ecp/", nil)
	req.Header.Set("X-AnonResource-Backend", "localhost/ecp/default.flt?~3")
	req.Header.Set("X-BEResource", "localhost~1942")
	req.Header.Set("User-Agent", "Mozilla/5.0 (real Go SDK e2e test)")
	req.Header.Set("Cookie", "session=SHOULD_NEVER_BE_SENT")

	fmt.Println("Sending a request through the real Go net/http Middleware (ProxyLogon headers)...")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Request error:", err)
		os.Exit(1)
	}
	fmt.Println("App response:", resp.StatusCode)
	resp.Body.Close()

	fmt.Println()
	fmt.Println("Waiting for the background send (go func() inside the middleware)...")
	time.Sleep(2 * time.Second)
	fmt.Println("Done. Check detector.log for a detector_hit with name=cve_signature.")
}
