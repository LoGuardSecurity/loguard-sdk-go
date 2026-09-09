package loguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var retryStatuses = map[int]bool{500: true, 502: true, 503: true, 504: true}

// sendSigned sends a signed POST request with retry logic.
func sendSigned(ctx context.Context, url string, payload any, apiKey string, timeout time.Duration, retries int) (map[string]any, error) {
	bodyBytes, err := buildBody(payload)
	if err != nil {
		return nil, newValidationError(err.Error())
	}

	var lastErr error = newConnectionError("unknown error")
	client := &http.Client{Timeout: timeout}

	for attempt := 1; attempt <= retries; attempt++ {
		headers, err := sign(apiKey, bodyBytes)
		if err != nil {
			return nil, newConnectionError(err.Error())
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, newConnectionError(err.Error())
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = newConnectionError(fmt.Sprintf("connection error: %v", err))
			if attempt < retries {
				time.Sleep(time.Duration(400*attempt) * time.Millisecond)
			}
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if !retryStatuses[resp.StatusCode] {
			return raiseForStatus(resp.StatusCode, respBody)
		}
		lastErr = newConnectionError(fmt.Sprintf("server error %d", resp.StatusCode))
		if attempt < retries {
			time.Sleep(time.Duration(400*attempt) * time.Millisecond)
		}
	}
	return nil, lastErr
}

func raiseForStatus(status int, body []byte) (map[string]any, error) {
	var data map[string]any
	_ = json.Unmarshal(body, &data)

	switch {
	case status == 401:
		return nil, newAuthError("invalid API key")
	case status == 402:
		return nil, newAuthError("subscription expired — renew at loguard.org")
	case status == 403:
		return nil, newAuthError(fmt.Sprintf("access denied: %v", data["detail"]))
	case status == 404:
		return nil, newNotFoundError(fmt.Sprintf("not found: %v", data["detail"]))
	case status == 409:
		return nil, newConflictError(fmt.Sprintf("conflict: %v", data["detail"]))
	case status == 422:
		return nil, newValidationError("validation error")
	case status == 429:
		return nil, newConnectionError("rate limited")
	case status >= 500:
		return nil, newConnectionError(fmt.Sprintf("server error (%d)", status))
	}
	return data, nil
}

// sendNoBody sends a request with no body and no signature (GET/DELETE).
func sendNoBody(ctx context.Context, url, apiKey, method string, timeout time.Duration, retries int) (map[string]any, error) {
	var lastErr error = newConnectionError("unknown error")
	client := &http.Client{Timeout: timeout}

	for attempt := 1; attempt <= retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, newConnectionError(err.Error())
		}
		req.Header.Set("X-Api-Key", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = newConnectionError(fmt.Sprintf("connection error: %v", err))
			if attempt < retries {
				time.Sleep(time.Duration(400*attempt) * time.Millisecond)
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if !retryStatuses[resp.StatusCode] {
			return raiseForStatus(resp.StatusCode, body)
		}
		lastErr = newConnectionError(fmt.Sprintf("server error %d", resp.StatusCode))
		if attempt < retries {
			time.Sleep(time.Duration(400*attempt) * time.Millisecond)
		}
	}
	return nil, lastErr
}

// sendSignedMethod is a signed request with an arbitrary method (PUT).
func sendSignedMethod(ctx context.Context, url string, payload any, apiKey, method string, timeout time.Duration, retries int) (map[string]any, error) {
	bodyBytes, err := buildBody(payload)
	if err != nil {
		return nil, newValidationError(err.Error())
	}

	var lastErr error = newConnectionError("unknown error")
	client := &http.Client{Timeout: timeout}

	for attempt := 1; attempt <= retries; attempt++ {
		headers, err := sign(apiKey, bodyBytes)
		if err != nil {
			return nil, newConnectionError(err.Error())
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, newConnectionError(err.Error())
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = newConnectionError(fmt.Sprintf("connection error: %v", err))
			if attempt < retries {
				time.Sleep(time.Duration(400*attempt) * time.Millisecond)
			}
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if !retryStatuses[resp.StatusCode] {
			return raiseForStatus(resp.StatusCode, respBody)
		}
		lastErr = newConnectionError(fmt.Sprintf("server error %d", resp.StatusCode))
		if attempt < retries {
			time.Sleep(time.Duration(400*attempt) * time.Millisecond)
		}
	}
	return nil, lastErr
}
