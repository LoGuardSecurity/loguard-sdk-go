package loguard

import (
	"strings"
	"time"
)

// Event is a security event.
type Event struct {
	Type       string         `json:"type"`
	IP         string         `json:"ip"`
	Path       string         `json:"path"`
	StatusCode int            `json:"status_code"`
	UserID     *string        `json:"user_id,omitempty"`
	Service    *string        `json:"service,omitempty"`
	Meta       map[string]any `json:"meta"`
	Timestamp  string         `json:"ts"`
}

// EventInput holds the input parameters for building an event.
type EventInput struct {
	Type       string
	IP         string
	Path       string
	StatusCode int
	UserID     string
	Service    string
	Meta       map[string]any
	Timestamp  time.Time
}

func buildEvent(in EventInput) (Event, error) {
	if in.Type == "" {
		return Event{}, newValidationError("event type is required")
	}
	if in.IP == "" {
		return Event{}, newValidationError("event ip is required")
	}
	if in.Path == "" {
		return Event{}, newValidationError("event path is required")
	}
	if in.StatusCode < 100 || in.StatusCode > 599 {
		return Event{}, newValidationError("statusCode must be in range 100..599")
	}

	p := strings.TrimSpace(in.Path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1024 {
		p = p[:1024]
	}

	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	meta := in.Meta
	if meta == nil {
		meta = map[string]any{}
	}

	var userID *string
	if in.UserID != "" {
		u := in.UserID
		if len(u) > 128 {
			u = u[:128]
		}
		userID = &u
	}

	var svc *string
	if in.Service != "" {
		s := strings.ToLower(strings.TrimSpace(in.Service))
		if len(s) > 64 {
			s = s[:64]
		}
		svc = &s
	}

	typ := strings.ToLower(strings.TrimSpace(in.Type))
	if len(typ) > 64 {
		typ = typ[:64]
	}
	ip := strings.TrimSpace(in.IP)
	if len(ip) > 64 {
		ip = ip[:64]
	}

	return Event{
		Type: typ, IP: ip, Path: p, StatusCode: in.StatusCode,
		UserID: userID, Service: svc, Meta: meta, Timestamp: ts.UTC().Format(time.RFC3339),
	}, nil
}
