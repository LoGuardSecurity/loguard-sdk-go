package loguard

import "fmt"

// LoGuardError is the SDK's base error type.
type LoGuardError struct {
	Kind    string
	Message string
}

func (e *LoGuardError) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

func newError(kind, msg string) *LoGuardError {
	return &LoGuardError{Kind: kind, Message: msg}
}

func newAuthError(msg string) *LoGuardError       { return newError("LoGuardAuthError", msg) }
func newConnectionError(msg string) *LoGuardError { return newError("LoGuardConnectionError", msg) }
func newValidationError(msg string) *LoGuardError { return newError("LoGuardValidationError", msg) }
func newNotFoundError(msg string) *LoGuardError   { return newError("LoGuardNotFoundError", msg) }
func newConflictError(msg string) *LoGuardError   { return newError("LoGuardConflictError", msg) }
func newQuotaError(msg string) *LoGuardError      { return newError("LoGuardQuotaError", msg) }
