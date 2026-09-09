package loguard

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// KnownExploitHeaders are headers that have historically carried real RCE
// exploits (ShellShock, ProxyLogon).
var KnownExploitHeaders = []string{"User-Agent", "Referer", "X-BEResource", "X-AnonResource-Backend"}

// forbiddenTrackHeaders is enforced in code, not just documented -- same
// protection as the Python/Node SDKs.
var forbiddenTrackHeaders = map[string]bool{
	"authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true, "proxy-authorization": true,
}

// MiddlewareOptions configures LoGuardMiddleware.
type MiddlewareOptions struct {
	TrackStatuses  map[int]bool
	TrackHeaders   []string
	TrustedProxies []string
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// GetRealIP resolves the real client IP, trusting X-Forwarded-For only
// when the request's direct peer is in trustedProxies.
func GetRealIP(r *http.Request, trustedProxies []string) string {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	for _, tp := range trustedProxies {
		if tp == clientIP {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				candidate := strings.TrimSpace(strings.Split(xff, ",")[0])
				if net.ParseIP(candidate) != nil {
					return candidate
				}
			}
		}
	}
	return clientIP
}

// Middleware returns a net/http middleware that tracks HTTP errors as
// LoGuard security events.
func (m *Monitor) Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	if opts.TrackStatuses == nil {
		opts.TrackStatuses = map[int]bool{400: true, 401: true, 403: true, 404: true, 429: true, 500: true, 502: true, 503: true}
	}

	var trackHeaders []string
	for _, h := range opts.TrackHeaders {
		lh := strings.ToLower(h)
		if forbiddenTrackHeaders[lh] {
			continue // never sent, even if explicitly requested
		}
		trackHeaders = append(trackHeaders, lh)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := GetRealIP(r, opts.TrustedProxies)

			rec := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(rec, r)

			if opts.TrackStatuses[rec.status] {
				eventType := "http_error"
				if rec.status == 401 {
					eventType = "login_failed"
				}
				meta := map[string]any{}
				if len(trackHeaders) > 0 {
					headers := map[string]string{}
					for _, h := range trackHeaders {
						if v := r.Header.Get(h); v != "" {
							if len(v) > 512 {
								v = v[:512]
							}
							headers[h] = v
						}
					}
					if len(headers) > 0 {
						meta["headers"] = headers
					}
				}
				// r.Context() gets cancelled by net/http as soon as this
				// handler returns, but the goroutine below is started
				// right here, before that return, and keeps running after
				// it. By the time sendSigned() inside m.Event() actually
				// tries to make the HTTP request, r.Context() is already
				// cancelled -- the request fails with "context canceled"
				// before it ever hits the network, the error gets
				// swallowed (it's a fire-and-forget call), and the event
				// is silently lost, every single time, with nothing in
				// the logs to explain why. A fire-and-forget goroutine's
				// lifetime shouldn't be tied to the request's lifetime --
				// that's the whole point of fire-and-forget -- so this
				// uses an independent context.Background() with its own
				// timeout instead.
				timeout := m.timeout
				if timeout <= 0 {
					timeout = 10 * time.Second
				}
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), timeout)
					defer cancel()
					_, _ = m.Event(ctx, EventInput{
						Type: eventType, IP: ip, Path: r.URL.Path, StatusCode: rec.status, Meta: meta,
					})
				}()
			}
		})
	}
}
