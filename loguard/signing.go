package loguard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const sdkVersion = "0.1.0"

// buildBody serializes the payload to JSON. Key order doesn't need to
// match byte-for-byte with the Python/Node versions -- what matters is
// internal consistency (whatever gets signed is exactly what gets sent);
// the server recomputes the signature over the bytes it actually received.
func buildBody(payload any) ([]byte, error) {
	return json.Marshal(payload)
}

// randomUUID generates a v4 UUID with no external dependencies.
func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// sign HMAC-SHA256-signs the request body, same protocol as the
// Python/Node/Rust SDKs. The timestamp guards against replay attacks
// (the server rejects requests older than 5 minutes).
func sign(apiKey string, bodyBytes []byte) (map[string]string, error) {
	timestamp := time.Now().Unix()
	signedPayload := append([]byte(fmt.Sprintf("%d.", timestamp)), bodyBytes...)

	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write(signedPayload)
	signature := hex.EncodeToString(mac.Sum(nil))

	reqID, err := randomUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request id: %w", err)
	}

	return map[string]string{
		"X-Api-Key":           apiKey,
		"X-LoGuard-Timestamp": fmt.Sprintf("%d", timestamp),
		"X-LoGuard-Signature": "sha256=" + signature,
		"X-Request-ID":        reqID,
		"Content-Type":        "application/json",
		"User-Agent":          "loguard-go-sdk/" + sdkVersion,
	}, nil
}
