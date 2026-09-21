// Package loguard is the official Go SDK for LoGuard security
// monitoring. Idiomatic Go style: an explicit NewMonitor() constructor
// instead of a global singleton (unlike the Python/Node SDKs) -- Go
// developers expect dependencies passed explicitly, not global state.
package loguard

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultBaseURL = "https://loguard.org"

// Monitor is the main LoGuard Go SDK client.
type Monitor struct {
	apiKey         string
	baseURL        string
	env            string
	timeout        time.Duration
	retries        int
	defaultService string
}

// InitOptions are the parameters for initializing a Monitor.
type InitOptions struct {
	APIKey  string
	BaseURL string
	Env     string
	Timeout time.Duration
	Retries int
	Service string
	// AllowInsecureTransport matches the Python SDK's behavior: refuse
	// plaintext http:// unless the caller explicitly opts in, since the
	// apiKey would otherwise go out in the clear on every request.
	AllowInsecureTransport bool
}

// NewMonitor creates and initializes a client. APIKey is required.
func NewMonitor(opts InitOptions) (*Monitor, error) {
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, newAuthError("apiKey is required")
	}
	if opts.BaseURL == "" {
		opts.BaseURL = defaultBaseURL
	}
	if !strings.HasPrefix(strings.ToLower(opts.BaseURL), "https://") {
		if !opts.AllowInsecureTransport {
			return nil, newValidationError(
				"BaseURL must use https:// -- your apiKey is sent on every request " +
					"and must not travel over plaintext HTTP. If you really need HTTP " +
					"(e.g. a local proxy on a trusted network during development), set " +
					"AllowInsecureTransport: true explicitly.",
			)
		}
		fmt.Fprintln(os.Stderr,
			"LoGuard SDK initialized with AllowInsecureTransport=true -- apiKey and "+
				"request signatures are being sent over plaintext. Use this ONLY for "+
				"local development on a trusted network, never against a real deployment.")
	}
	if opts.Env == "" {
		opts.Env = "production"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Retries == 0 {
		opts.Retries = 3
	}

	// Falls back to whatever OpenTelemetry already settled on
	// (OTEL_SERVICE_NAME), so a deployment with N microservices sets this
	// once in its infra (Helm/docker-compose/ECS task def) rather than
	// once per service in code. Deliberately not falling back to hostname
	// -- in Docker/k8s that's usually a container/pod ID with a random
	// suffix that changes on every restart or replica, which would break
	// grouping "one service, many instances" instead of solving it.
	defaultService := opts.Service
	if defaultService == "" {
		defaultService = os.Getenv("OTEL_SERVICE_NAME")
	}
	if defaultService == "" {
		defaultService = os.Getenv("SERVICE_NAME")
	}

	m := &Monitor{
		apiKey:         strings.TrimSpace(opts.APIKey),
		baseURL:        strings.TrimRight(opts.BaseURL, "/"),
		env:            opts.Env,
		timeout:        opts.Timeout,
		retries:        opts.Retries,
		defaultService: defaultService,
	}
	return m, nil
}

func (m *Monitor) ingestURL() string { return m.baseURL + "/v1/ingest" }

// Event sends a single security event (blocking call).
func (m *Monitor) Event(ctx context.Context, in EventInput) (map[string]any, error) {
	if in.Service == "" {
		in.Service = m.defaultService
	}
	ev, err := buildEvent(in)
	if err != nil {
		return nil, err
	}
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	ev.Meta["env"] = m.env
	return sendSigned(ctx, m.ingestURL(), map[string]any{"events": []Event{ev}}, m.apiKey, m.timeout, m.retries)
}

// EventBatch sends several events in a single request.
func (m *Monitor) EventBatch(ctx context.Context, ins []EventInput) (map[string]any, error) {
	events := make([]Event, 0, len(ins))
	for _, in := range ins {
		if in.Service == "" {
			in.Service = m.defaultService
		}
		ev, err := buildEvent(in)
		if err != nil {
			return nil, err
		}
		if ev.Meta == nil {
			ev.Meta = map[string]any{}
		}
		ev.Meta["env"] = m.env
		events = append(events, ev)
	}
	return sendSigned(ctx, m.ingestURL(), map[string]any{"events": events}, m.apiKey, m.timeout, m.retries)
}
