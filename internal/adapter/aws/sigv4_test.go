package aws

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
)

// The published Signature Version 4 test suite (aws-sig-v4-test-suite) and
// the IAM example of the AWS General Reference: the documented example
// credentials, 2015-08-30T12:36:00Z, region us-east-1. The expected values
// were also recomputed with an independent implementation before being
// written here.
// sigExample is AWS's published example value of the documentation
// credentials (not a credential).
const sigExample = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

var (
	vectorTime  = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	vectorCreds = Credentials{
		AccessKeyID:     credential.NewSecret("AKIDEXAMPLE"),
		SecretAccessKey: credential.NewSecret(sigExample),
	}
)

func TestSigV4Vectors(t *testing.T) {
	for _, tc := range []struct {
		name, method, url, contentType, body, service, want string
	}{
		{
			name: "get-vanilla", method: "GET", url: "https://example.amazonaws.com/", service: "service",
			want: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			name: "post-vanilla", method: "POST", url: "https://example.amazonaws.com/", service: "service",
			want: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
		},
		{
			name: "get-vanilla-query-order-key-case", method: "GET", url: "https://example.amazonaws.com/?Param2=value2&Param1=value1", service: "service",
			want: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
		},
		{
			name: "post-x-www-form-urlencoded", method: "POST", url: "https://example.amazonaws.com/", service: "service",
			contentType: "application/x-www-form-urlencoded", body: "Param1=value1",
			want: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
		},
		{
			name: "iam-general-reference", method: "GET", url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", service: "iam",
			contentType: "application/x-www-form-urlencoded; charset=utf-8",
			want:        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.body != "" {
				body = []byte(tc.body)
			}
			req, err := http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			sign(req, body, vectorCreds, "us-east-1", tc.service, vectorTime)
			if got := req.Header.Get("Authorization"); got != tc.want {
				t.Errorf("Authorization\n got %s\nwant %s", got, tc.want)
			}
			if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
				t.Errorf("X-Amz-Date %s", got)
			}
		})
	}
}

func TestSigV4SessionTokenIsSigned(t *testing.T) {
	c := vectorCreds
	c.SessionToken = credential.NewSecret("synthetic-session-value")
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	sign(req, nil, c, "us-east-1", "service", vectorTime)
	if req.Header.Get("X-Amz-Security-Token") != "synthetic-session-value" {
		t.Fatal("session token header missing")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "SignedHeaders=host;x-amz-date;x-amz-security-token,") {
		t.Fatalf("session token not signed: %s", req.Header.Get("Authorization"))
	}
}

func TestURIEncode(t *testing.T) {
	for in, want := range map[string]string{
		"a b":   "a%20b",
		"A-_.~": "A-_.~",
		"a/b:c": "a%2Fb%3Ac",
		"é":     "%C3%A9",
		"a+b=c": "a%2Bb%3Dc",
	} {
		if got := uriEncode(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Fatal("a request was sent")
	return nil, errors.New("unreachable")
}

// TestOnlyReadOperations: an operation outside the read-only list (for
// example ACM ExportCertificate, which returns a private key) is refused
// before anything is sent.
func TestOnlyReadOperations(t *testing.T) {
	clk := clock.NewFake(vectorTime)
	c := &client{hc: &http.Client{Transport: failTransport{t}}, creds: vectorCreds, clk: clk, lim: adapter.NewLimiter(clk, 0), suffix: "amazonaws.com"}
	for _, op := range []string{"ExportCertificate", "ImportCertificate", "DeleteCertificate", "UploadServerCertificate", "ModifyListener", "RequestCertificate"} {
		var out struct{}
		if err := c.acm(context.Background(), "us-east-1", op, struct{}{}, &out); !errors.Is(err, ErrNotReadOnly) {
			t.Errorf("%s: %v", op, err)
		}
	}
	for op := range readOnlyOps {
		if !strings.HasPrefix(op, "List") && !strings.HasPrefix(op, "Describe") && !strings.HasPrefix(op, "Get") {
			t.Errorf("%s is on the read-only list but is not a List, Describe or Get operation", op)
		}
	}
}

func TestErrorCode(t *testing.T) {
	for body, want := range map[string]string{
		`{"__type":"ThrottlingException","message":"Rate exceeded"}`:                                            "ThrottlingException",
		`{"__type":"com.amazonaws.acm#AccessDeniedException","message":"x"}`:                                    "AccessDeniedException",
		`<ErrorResponse><Error><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>`: "Throttling",
		`<Response><Errors><Error><Code>AuthFailure</Code></Error></Errors></Response>`:                         "AuthFailure",
		`{"__type":"<script>"}`: "",
		`not an error body`:     "",
	} {
		if got := errorCode([]byte(body)); got != want {
			t.Errorf("%s: %q, want %q", body, got, want)
		}
	}
	if !errors.Is(&APIError{Op: "x", Status: 400, Code: "UnrecognizedClientException"}, ErrAuth) {
		t.Error("UnrecognizedClientException is not ErrAuth")
	}
	if errors.Is(&APIError{Op: "x", Status: 400, Code: "ThrottlingException"}, ErrAuth) {
		t.Error("ThrottlingException is ErrAuth")
	}
}
