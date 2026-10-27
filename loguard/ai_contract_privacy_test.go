package loguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAIContractPrivacy(t *testing.T) {
	inputs := []EventInput{
		{Type: "ai_llm_request", IP: "203.0.113.10", Path: "/ai/test", StatusCode: 200,
			Meta: map[string]any{"prompt": "Synthetic հայկական request"}},
		{Type: "ai_llm_response", IP: "203.0.113.10", Path: "/ai/test", StatusCode: 200,
			Meta: map[string]any{"response": "Synthetic response"}},
		{Type: "ai_tool_call", IP: "203.0.113.10", Path: "/ai/test", StatusCode: 200,
			Meta: map[string]any{"tool_name": "search_documents", "tool_args": map[string]any{}}},
	}
	for _, input := range inputs {
		t.Run(input.Type, func(t *testing.T) {
			event, err := buildEvent(input)
			if err != nil || event.Type != input.Type {
				t.Fatal("event contract")
			}
			body, err := buildBody(map[string]any{"events": []Event{event}})
			if err != nil {
				t.Fatal("encode")
			}
			headers, err := sign("synthetic-key", body)
			if err != nil {
				t.Fatal("sign")
			}
			mac := hmac.New(sha256.New, []byte("synthetic-key"))
			mac.Write(append([]byte(headers["X-LoGuard-Timestamp"]+"."), body...))
			if headers["X-LoGuard-Signature"] != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
				t.Fatal("signature mismatch")
			}
			if input.Type == "ai_tool_call" && !strings.Contains(string(body), `"tool_args":{}`) {
				t.Fatal("empty tool arguments must be an object")
			}
		})
	}
	for _, status := range []int{403, 404, 409, 422, 429, 500} {
		_, err := raiseForStatus(status, []byte(`{"detail":{"input":"SYNTHETIC_PRIVATE_MARKER"}}`))
		if err == nil || strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MARKER") {
			t.Fatal("error response content escaped into an exception")
		}
		if _, ok := err.(*LoGuardError); !ok {
			t.Fatal("SDK error type must be preserved")
		}
	}
}
