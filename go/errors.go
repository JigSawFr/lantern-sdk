// SPDX-License-Identifier: MIT

package lantern

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/JigSawFr/lantern-sdk/go/internal/model"
)

// DocumentError is a document that breaks the specification: malformed JSON, a missing field, a
// field of the wrong type, or one beyond the limits of SPEC.md § 13. Where says which field, as a
// path (homebrew.package.manifest[2].path).
type DocumentError = model.Error

// The kinds of error this library gives; test them with errors.Is.
var (
	ErrUnauthorized       = errors.New("lantern: unauthorized (401)")
	ErrSignatureRefused   = errors.New("lantern: a request's signature was refused (401)")
	ErrSignatureRequired  = errors.New("lantern: signature required")
	ErrSignatureInvalid   = errors.New("lantern: signature invalid")
	ErrSignatureExpired   = errors.New("lantern: signature expired")
	ErrSignatureReplayed  = errors.New("lantern: signature replayed")
	ErrBadRequest         = errors.New("lantern: bad request (400, 405, 416)")
	ErrForbidden          = errors.New("lantern: forbidden (403)")
	ErrAccountFrozen      = errors.New("lantern: account frozen")
	ErrNotFound           = errors.New("lantern: not found (404)")
	ErrConflict           = errors.New("lantern: conflict (409)")
	ErrGone               = errors.New("lantern: gone (410)")
	ErrPreconditionFailed = errors.New("lantern: precondition failed (412)")
	ErrTooLarge           = errors.New("lantern: too large (413)")
	ErrUnprocessable      = errors.New("lantern: unprocessable (422)")
	ErrSlowDown           = errors.New("lantern: slow down (429)")
	ErrServer             = errors.New("lantern: server error (5xx)")
	ErrUnavailable        = errors.New("lantern: unavailable (503)")
	ErrNewerSchema        = errors.New("lantern: a document of a newer schema")
	ErrIntegrity          = errors.New("lantern: a download that is not what its document says")
	ErrTransport          = errors.New("lantern: transport failed")
	ErrPinMismatch        = errors.New("lantern: the server's key is not the one pinned")
	ErrInsecureTransport  = errors.New("lantern: plain HTTP to an address that is not a loopback one")
	ErrUnexpectedResponse = errors.New("lantern: an answer the protocol does not allow here")
)

// Problem errors form a tree: AccountFrozen is a Forbidden; the signature errors are Unauthorized
// and SignatureRefused; Unavailable is a ServerError.
var parents = map[error][]error{
	ErrSignatureRefused:  {ErrUnauthorized},
	ErrSignatureRequired: {ErrSignatureRefused},
	ErrSignatureInvalid:  {ErrSignatureRefused},
	ErrSignatureExpired:  {ErrSignatureRefused},
	ErrSignatureReplayed: {ErrSignatureRefused},
	ErrAccountFrozen:     {ErrForbidden},
	ErrUnavailable:       {ErrServer},
	ErrPinMismatch:       {ErrTransport},
	ErrInsecureTransport: {ErrTransport},
}

// DetailLimit bounds the detail of a problem a client keeps, in bytes.
const DetailLimit = 512

// ProblemError is a server's error answer (SPEC.md § 12): its Status, its Code when this library
// knows it ("" otherwise: act on the status), Detail for people (bounded, without control
// characters), and RetryAfter in seconds when the server said (0 otherwise). Problem keeps the
// document as the server sent it. A server's answer is the kind of its status (ErrNotFound for
// 404, ErrGone for 410…), whatever its code, as SPEC.md § 12 asks:
//
//	var p *lantern.ProblemError
//	if errors.As(err, &p) { ... }
//	if errors.Is(err, lantern.ErrNotFound) { ... }
type ProblemError struct {
	Status     int
	Code       string
	Detail     string
	RetryAfter int
	Problem    *Problem
	Headers    map[string]string
	Kind       error
}

func (e *ProblemError) Error() string {
	code := e.Code
	if code == "" {
		code = "error"
	}
	s := strconv.Itoa(e.Status) + " " + code
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Is reports whether the error is of the kind target, or of a kind it descends from.
func (e *ProblemError) Is(target error) bool { return kindIs(e.Kind, target) }

// Header is the answer's header name (compared without regard to case), or "".
func (e *ProblemError) Header(name string) string { return header(e.Headers, name) }

func kindIs(kind, target error) bool {
	if kind == nil {
		return false
	}
	if kind == target {
		return true
	}
	for _, p := range parents[kind] {
		if kindIs(p, target) {
			return true
		}
	}
	return false
}

var byStatus = map[int]error{
	400: ErrBadRequest, 401: ErrUnauthorized, 403: ErrForbidden, 404: ErrNotFound, 405: ErrBadRequest,
	409: ErrConflict, 410: ErrGone, 412: ErrPreconditionFailed, 413: ErrTooLarge, 416: ErrBadRequest,
	422: ErrUnprocessable, 429: ErrSlowDown, 500: ErrServer, 503: ErrUnavailable,
}

var signatureKinds = map[string]error{
	"signature_required": ErrSignatureRequired,
	"signature_invalid":  ErrSignatureInvalid,
	"signature_expired":  ErrSignatureExpired,
	"signature_replayed": ErrSignatureReplayed,
}

// NewProblemError is the error for an error answer: its kind by status, its problem document when
// the body is one (an unreadable body still gives the status).
func NewProblemError(status int, body []byte, headers map[string]string) *ProblemError {
	e := &ProblemError{Status: status, Headers: headers}
	if doc, err := LoadJSON(body, LoadOptions{Limit: 1 << 16, Where: "problem"}); err == nil {
		var p Problem
		if b, err := Canonical(doc); err == nil && p.UnmarshalJSON(b) == nil {
			e.Problem = &p
		}
	}
	e.Kind = byStatus[status]
	if e.Kind == nil {
		if status >= 500 {
			e.Kind = ErrServer
		} else {
			e.Kind = errors.New("lantern: error answer")
		}
	}
	if p := e.Problem; p != nil {
		for _, c := range ErrorCodes {
			if c == p.Code {
				e.Code = c
			}
		}
		text := ""
		if p.Detail != nil {
			text = *p.Detail
		}
		if text == "" && p.Title != nil {
			text = *p.Title
		}
		e.Detail = Printable(text, DetailLimit)
		if e.Kind == ErrForbidden && e.Code == "account_frozen" {
			e.Kind = ErrAccountFrozen
		}
		if k, ok := signatureKinds[e.Code]; ok && e.Kind == ErrUnauthorized {
			e.Kind = k
		}
	}
	if s := strings.TrimSpace(header(headers, "Retry-After")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && isDigits(s) {
			e.RetryAfter = n
		}
	}
	return e
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func header(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// NewerSchemaError is a document of a newer schema than this library reads: by SPEC.md § 3.2 it is
// absent (the feature is unavailable), not an error of the server. The caller treats what it asked
// for as missing; errors.Is(err, ErrNewerSchema) tells.
type NewerSchemaError struct {
	What   string
	Schema int64
}

func (e *NewerSchemaError) Error() string {
	return fmt.Sprintf("%s: schema %d, newer than this library reads: treated as absent", e.What, e.Schema)
}

// Is reports ErrNewerSchema.
func (e *NewerSchemaError) Is(target error) bool { return target == ErrNewerSchema }
