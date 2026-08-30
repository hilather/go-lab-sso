package domainerr

import (
	"errors"
	"fmt"
)

const (
	CodeRevisionConflict = "revision_conflict"
	CodeValidation       = "validation_failed"
	CodeNotFound         = "not_found"
	CodeConflict         = "conflict"
	CodeInternal         = "internal"
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeProtocol         = "unsupported_protocol_version"
)

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func RevisionConflict(current, expected string) *Error {
	return &Error{
		Code:    CodeRevisionConflict,
		Message: fmt.Sprintf("active revision %s does not match expectedRevision %s", current, expected),
	}
}

func Validation(msg string) *Error {
	return &Error{Code: CodeValidation, Message: msg}
}

func NotFound(msg string) *Error {
	return &Error{Code: CodeNotFound, Message: msg}
}

func Conflict(msg string) *Error {
	return &Error{Code: CodeConflict, Message: msg}
}

func Unauthorized(msg string) *Error {
	return &Error{Code: CodeUnauthorized, Message: msg}
}

func Forbidden(msg string) *Error {
	return &Error{Code: CodeForbidden, Message: msg}
}

func Protocol(msg string) *Error {
	return &Error{Code: CodeProtocol, Message: msg}
}

func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
