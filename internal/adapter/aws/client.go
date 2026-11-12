package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/retry"
)

// ErrAuth marks an answer that says the credentials were refused or lack a
// permission. It is not retried.
var ErrAuth = errors.New("AWS refused the credentials or the permission (check the read-only policy in docs/cloud-adapters.md)")

// ErrNotReadOnly is returned for an operation outside the read-only list.
var ErrNotReadOnly = errors.New("operation is not on the adapter's read-only list")

// readOnlyOps are the only operations the adapter may call. Every one of
// them reads; none returns private keys (ACM ExportCertificate, which
// does, is deliberately absent).
var readOnlyOps = map[string]bool{
	"ListCertificates":             true,
	"DescribeCertificate":          true,
	"GetCertificate":               true,
	"DescribeLoadBalancers":        true,
	"DescribeListeners":            true,
	"DescribeListenerCertificates": true,
	"ListServerCertificates":       true,
	"GetServerCertificate":         true,
}

var throttleCodes = map[string]bool{
	"Throttling": true, "ThrottlingException": true, "ThrottledException": true,
	"RequestLimitExceeded": true, "TooManyRequestsException": true, "RequestThrottled": true,
	"RequestThrottledException": true, "SlowDown": true,
}

var authCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true, "UnrecognizedClientException": true,
	"InvalidClientTokenId": true, "SignatureDoesNotMatch": true, "InvalidSignatureException": true,
	"ExpiredToken": true, "ExpiredTokenException": true, "IncompleteSignature": true,
	"AuthFailure": true, "MissingAuthenticationToken": true, "UnauthorizedOperation": true,
}

var awsRetry = retry.Policy{Attempts: 5, Base: time.Second, Max: 30 * time.Second, MaxRetryAfter: 2 * time.Minute}

const (
	maxBody      = 64 << 20
	maxErrorBody = 1 << 20
)

// APIError is a non-successful AWS answer. It names the operation, status
// and AWS error code only; never a header, a credential or a signature.
type APIError struct {
	Op     string
	Status int
	Code   string
}

// Error names the operation, status and error code.
func (e *APIError) Error() string {
	return fmt.Sprintf("aws: %s: HTTP %d %s", e.Op, e.Status, e.Code)
}

// Unwrap makes errors.Is(err, ErrAuth) true for authentication answers.
func (e *APIError) Unwrap() error {
	if authCodes[e.Code] || e.Status == http.StatusUnauthorized || (e.Status == http.StatusForbidden && !throttleCodes[e.Code]) {
		return ErrAuth
	}
	return nil
}

func (e *APIError) throttled() bool {
	return throttleCodes[e.Code] || retry.Retryable(e.Status)
}

type client struct {
	hc     *http.Client
	creds  Credentials
	clk    clock.Clock
	lim    *adapter.Limiter
	suffix string
}

// endpoint returns the regional API host of an AWS service.
func (c *client) endpoint(prefix, region string) string {
	if region == "" {
		return prefix + "." + c.suffix
	}
	return prefix + "." + region + "." + c.suffix
}

// acm calls a Certificate Manager operation (AWS JSON 1.1 protocol).
func (c *client) acm(ctx context.Context, region, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	b, err := c.do(ctx, op, region, "acm", c.endpoint("acm", region), http.MethodPost, nil, body, map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": "CertificateManager." + op,
	})
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("aws: %s: decode: %w", op, err)
	}
	return nil
}

// query calls an AWS Query protocol operation (GET, XML answer).
func (c *client) query(ctx context.Context, signRegion, service, host, op, version string, params url.Values, out any) error {
	q := url.Values{}
	for k, v := range params {
		q[k] = v
	}
	q.Set("Action", op)
	q.Set("Version", version)
	b, err := c.do(ctx, op, signRegion, service, host, http.MethodGet, q, nil, nil)
	if err != nil {
		return err
	}
	if err := xml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("aws: %s: decode: %w", op, err)
	}
	return nil
}

// do sends one signed request with rate limiting and retries (429, 5xx and
// throttling codes; Retry-After honoured). It signs again on every attempt.
func (c *client) do(ctx context.Context, op, region, service, host, method string, q url.Values, body []byte, hdr map[string]string) ([]byte, error) {
	if !readOnlyOps[op] {
		return nil, fmt.Errorf("aws: %s: %w", op, ErrNotReadOnly)
	}
	for attempt := 0; ; attempt++ {
		if err := c.lim.Wait(ctx); err != nil {
			return nil, err
		}
		u := &url.URL{Scheme: "https", Host: host, Path: "/", RawQuery: q.Encode()}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return nil, err
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		sign(req, body, c.creds, region, service, c.clk.Now())
		resp, err := c.hc.Do(req)
		var (
			wait    http.Header
			lastErr error
		)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("aws: %s: %s", op, c.redact(err.Error()))
		} else {
			if resp.StatusCode == http.StatusOK {
				b, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
				_ = resp.Body.Close()
				if rerr != nil {
					return nil, fmt.Errorf("aws: %s: read: %s", op, c.redact(rerr.Error()))
				}
				return b, nil
			}
			eb, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
			_ = resp.Body.Close()
			ae := &APIError{Op: op, Status: resp.StatusCode, Code: errorCode(eb)}
			if !ae.throttled() {
				return nil, ae
			}
			wait, lastErr = resp.Header, ae
		}
		if attempt >= awsRetry.Attempts {
			return nil, fmt.Errorf("giving up after %d attempts: %w", attempt+1, lastErr)
		}
		d, ok := awsRetry.Wait(attempt, wait, c.clk.Now())
		if !ok {
			return nil, lastErr
		}
		if err := c.clk.Sleep(ctx, d); err != nil {
			return nil, err
		}
	}
}

func (c *client) redact(s string) string {
	return adapter.Redact(s, c.creds.AccessKeyID.Reveal(), c.creds.SecretAccessKey.Reveal(), c.creds.SessionToken.Reveal())
}

// errorCode extracts the AWS error code of a JSON (__type, code) or XML
// (<Code>) error body. Only the code is kept, never the message.
func errorCode(b []byte) string {
	var j struct {
		Type string `json:"__type"`
		Code string `json:"code"`
	}
	if json.Unmarshal(b, &j) == nil {
		code := j.Type
		if code == "" {
			code = j.Code
		}
		if i := strings.LastIndexByte(code, '#'); i >= 0 {
			code = code[i+1:]
		}
		return safeCode(code)
	}
	var x struct {
		Code  string `xml:"Error>Code"`
		Code2 string `xml:"Errors>Error>Code"`
	}
	if xml.Unmarshal(b, &x) == nil {
		if x.Code != "" {
			return safeCode(x.Code)
		}
		return safeCode(x.Code2)
	}
	return ""
}

// safeCode keeps an error code only when it looks like one.
func safeCode(s string) string {
	if len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if !codeRune(r) {
			return ""
		}
	}
	return s
}

func codeRune(r rune) bool {
	switch {
	case 'A' <= r && r <= 'Z', 'a' <= r && r <= 'z', '0' <= r && r <= '9', r == '.', r == '_':
		return true
	}
	return false
}
