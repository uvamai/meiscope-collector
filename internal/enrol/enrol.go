// Package enrol is the collector's client of the core's enrolment surface
// (collector contract 0.9.0): POST /collector/v1/enrol, which redeems a
// one-time token for a client certificate, and POST /collector/v1/certificate,
// which renews it over mTLS. Only a CSR is ever sent; the private key stays
// on the host. The token is a credential: it is never logged or returned in
// an error.
package enrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/redirect"
)

// Endpoints below the core base URL.
const (
	EnrolPath       = "/collector/v1/enrol"
	CertificatePath = "/collector/v1/certificate"
	maxAnswerBytes  = 1 << 20
	maxProblemBytes = 64 << 10
)

// ErrTokenRefused is the core's 401 on POST /enrol: the token is invalid,
// expired or already used (the reason is only in the tenant's audit log).
var ErrTokenRefused = errors.New("the enrolment token is invalid, expired or already used: ask for a new one")

// ErrNameTaken is the core's 409 on POST /enrol: the tenant already has a
// collector of the token's name. The token stays unused.
var ErrNameTaken = errors.New("the tenant already has a collector of this token's name (the token is still unused)")

// Error is any other refusal by the core, with its problem detail.
type Error struct {
	Status int
	Title  string
	Detail string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("core answered HTTP %d", e.Status)
	if e.Title != "" {
		msg += ": " + e.Title
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// Retryable reports whether the same request may succeed later (503: the
// CA did not issue or enrolment is not configured yet).
func (e *Error) Retryable() bool { return e.Status == http.StatusServiceUnavailable }

// Client calls the core's enrolment endpoints.
type Client struct {
	base      *url.URL
	hc        *http.Client
	userAgent string
}

// New returns a client for the core at base, an absolute https URL. hc must
// trust the core's server certificate; for Renew it must also present the
// collector certificate (identity.Store.Transport).
func New(base string, hc *http.Client, userAgent string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("core URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("core URL must be an absolute https URL, got %q", base)
	}
	if hc == nil {
		return nil, errors.New("enrol: no HTTP client")
	}
	// Never follow a redirect: the token and the CSR go to the configured
	// core only.
	return &Client{base: u, hc: redirect.Client(hc), userAgent: userAgent}, nil
}

// Enrol redeems token with csr (PEM) and returns the issued credentials.
// It does not retry: a token is single use, so a lost answer must not be
// replayed blindly.
func (c *Client) Enrol(ctx context.Context, token, csr string) (identity.Credentials, error) {
	body, err := json.Marshal(struct {
		Token string `json:"token"`
		CSR   string `json:"csr"`
	}{token, csr})
	if err != nil {
		return identity.Credentials{}, err
	}
	cred, err := c.post(ctx, EnrolPath, body)
	switch {
	case err == nil:
		return cred, nil
	case isStatus(err, http.StatusUnauthorized):
		return identity.Credentials{}, ErrTokenRefused
	case isStatus(err, http.StatusConflict):
		return identity.Credentials{}, ErrNameTaken
	default:
		return identity.Credentials{}, fmt.Errorf("enrol: %w", err)
	}
}

// Renew asks for a new certificate for csr (PEM). The request is
// authenticated by the collector's current certificate (mTLS).
func (c *Client) Renew(ctx context.Context, csr string) (identity.Credentials, error) {
	body, err := json.Marshal(struct {
		CSR string `json:"csr"`
	}{csr})
	if err != nil {
		return identity.Credentials{}, err
	}
	cred, err := c.post(ctx, CertificatePath, body)
	if err != nil {
		return identity.Credentials{}, fmt.Errorf("renew certificate: %w", err)
	}
	return cred, nil
}

func isStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

func (c *Client) post(ctx context.Context, path string, body []byte) (identity.Credentials, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), bytes.NewReader(body))
	if err != nil {
		return identity.Credentials{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return identity.Credentials{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := redirect.Check(resp); err != nil {
		return identity.Credentials{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		return identity.Credentials{}, readError(resp)
	}
	var cred identity.Credentials
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAnswerBytes)).Decode(&cred); err != nil {
		return identity.Credentials{}, fmt.Errorf("decode answer: %w", err)
	}
	return cred, nil
}

// readError turns a non-201 answer into an *Error, keeping the problem
// detail (application/problem+json) when there is one.
func readError(resp *http.Response) *Error {
	e := &Error{Status: resp.StatusCode}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxProblemBytes))
	if strings.Contains(resp.Header.Get("Content-Type"), "json") {
		var p struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(b, &p) == nil {
			e.Title, e.Detail = p.Title, p.Detail
		}
	}
	return e
}
