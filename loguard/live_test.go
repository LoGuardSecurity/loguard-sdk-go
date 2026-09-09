package loguard

import (
	"context"
	"os"
	"testing"
	"time"
)

// liveAPIKey reads the key for live tests from the environment. These
// tests are skipped entirely if it isn't set, so `go test` works out of
// the box with no live credentials anywhere in source control.
func liveAPIKey(t *testing.T) string {
	key := os.Getenv("LOGUARD_API_KEY")
	if key == "" {
		t.Skip("LOGUARD_API_KEY not set -- skipping live test")
	}
	return key
}

// TestLiveIngest is a real test against a local server. Skipped
// automatically in CI (-short flag), run manually to check signing
// protocol compatibility.
func TestLiveIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	apiKey := liveAPIKey(t)

	payload := map[string]any{
		"events": []map[string]any{{
			"type":        "test_go_sdk",
			"ip":          "203.0.113.7",
			"path":        "/test-go",
			"status_code": 401,
			"ts":          time.Now().UTC().Format(time.RFC3339),
			"meta":        map[string]any{},
		}},
	}

	result, err := sendSigned(
		context.Background(),
		"http://localhost:8000/v1/ingest",
		payload,
		apiKey,
		10*time.Second,
		3,
	)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got: %+v", result)
	}
	t.Logf("Success: %+v", result)
}

func TestLiveMonitorEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	apiKey := liveAPIKey(t)

	m, err := NewMonitor(InitOptions{
		APIKey:  apiKey,
		BaseURL: "http://localhost:8000",
	})
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	result, err := m.Event(context.Background(), EventInput{
		Type: "test_go_monitor", IP: "203.0.113.8", Path: "/test-go-monitor", StatusCode: 401,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	t.Logf("Success: %+v", result)
}
