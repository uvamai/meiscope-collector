# Cloud adapters: AWS and Cloudflare

Two read-only adapters (WP1.2; FR-DISC-024, 025, 026 and 030) read
certificates and their bindings from cloud provider APIs the customer already
uses. They follow the rules in [adapters.md](adapters.md): they only read,
they never scan or connect to anything but the provider's API endpoints, and
credentials come just in time from `credential.Source`.

**Status: behind a feature switch.** Their observations use the target kind
`cloud_resource`, which the core's contract 0.9.0 does not have yet. It is
proposed in [`api/proposed/collector-0.10.0-proposed.yaml`](../api/proposed/collector-0.10.0-proposed.yaml).
Until the core adopts it, leave `MEISCOPE_FEATURE_CLOUD_RESOURCE_V1` off (the
default): the adapters then read, count and log, send nothing, and keep their
cursor so nothing is lost for the day the switch is turned on.

Fixtures are **synthetic** (no test accounts were available); see
`testdata/adapters/aws/README.md` and `testdata/adapters/cloudflare/README.md`
for what must be re-recorded.

## What is observed

| Source | `cloud.service` | `resource_id` | Outcome | Evidence |
|---|---|---|---|---|
| ACM certificate | `acm` | certificate ARN | `cert_seen` when issued (public certificate and chain from `GetCertificate`), else `reached` | `hostnames` (SANs), `bindings` (`InUseBy`: ELB, CloudFront, API Gateway ARNs), `renewal`, `cloud_certificate` |
| ALB/NLB listener (HTTPS, TLS) | `elbv2_listener` | listener ARN | `reached` | `endpoint` (DNS name, port, protocol, scheme), `bindings` (every certificate, default first, ACM or IAM) |
| Classic ELB listener (HTTPS, SSL) | `elb_listener` | load balancer ARN + `/listener/<port>` (Classic listeners have no ARN; the account is taken from the certificate ARN) | `reached` | as above |
| IAM server certificate | `iam_server_certificate` | ARN (global, no region) | `cert_seen` | `renewal: manual` |
| Cloudflare certificate pack | `certificate_pack` | pack ID (`account` = zone ID) | `reached` (the API returns metadata, not the certificate) | `hostnames`, `bindings` (the pack's edge certificates), `cloud_certificate` (primary certificate's issuer, serial, expiry), `renewal` |
| Cloudflare custom certificate | `custom_certificate` | certificate ID | `reached` | `hostnames`, `cloud_certificate`, `renewal: manual` |
| Cloudflare Origin CA certificate | `origin_ca_certificate` | certificate ID | `cert_seen` (public certificate from the API) | `hostnames`, `renewal: manual` |

`target.host` is the API host that was read (for example
`acm.ap-southeast-2.amazonaws.com`, `iam.amazonaws.com`, `api.cloudflare.com`).

### Renewal mode

Set only from what the source proves, never guessed:

| Source | `renewal.mode` |
|---|---|
| ACM `Type` AMAZON_ISSUED or PRIVATE and `RenewalEligibility` ELIGIBLE | `external_automated`, `managed_by: aws_acm` (the core sets renewal_mode external_automated) |
| ACM `Type` IMPORTED | `manual` (ACM never renews imported certificates) |
| any other ACM certificate (for example INELIGIBLE) | `unknown` |
| IAM server certificate | `manual` |
| Cloudflare pack of type universal, advanced or total_tls | `external_automated`, `managed_by: cloudflare` |
| other Cloudflare pack types | `unknown` |
| Cloudflare custom and Origin CA certificates | `manual` |

`renewal.status` and `renewal.eligibility` carry the source's own values
(`RenewalSummary.RenewalStatus`, `RenewalEligibility`, pack `status`).

## AWS

```json
[{"name": "aws-prod", "adapter": "aws",
  "settings": {"regions": "ap-southeast-2,us-east-1"},
  "credentials": {"access_key_id": "aws_ro_key_id", "secret_access_key": "aws_ro_secret", "session_token": "aws_ro_session"}}]
```

| Setting | Meaning |
|---|---|
| `regions` | required; comma-separated. Include `us-east-1` for CloudFront certificates. |
| `services` | subset of `acm,elb,iam`; default all. IAM is global and read once. |
| `rate_per_second` | per adapter instance, default 5 (below ACM's and ELB's documented request rates). |
| `refresh_hours` | unchanged resources are re-sent this often (default 24; `0` sends only changes). |
| `max_pages` | page cap per listing (default 10000). |

**Credentials.** `access_key_id` and `secret_access_key`, plus
`session_token` for temporary role-session credentials (recommended: the
customer's vault issues short-lived credentials of a read-only role). The
adapter does not call STS itself. Requests are signed with Signature Version
4, implemented in `internal/adapter/aws/sigv4.go` (about 120 lines, tested
against the published AWS test vectors; no AWS SDK dependency).

**Minimum permissions** (read-only; no `acm:ExportCertificate`, which returns
private keys and which the adapter refuses to call):

```json
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
  "acm:ListCertificates", "acm:DescribeCertificate", "acm:GetCertificate",
  "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners",
  "elasticloadbalancing:DescribeListenerCertificates",
  "iam:ListServerCertificates", "iam:GetServerCertificate"]}]}
```

**Never touches:** private keys, any write or import operation, any endpoint
other than `acm.<region>.amazonaws.com`, `elasticloadbalancing.<region>.amazonaws.com`
and `iam.amazonaws.com`. The operation list is fixed in code (`readOnlyOps`)
and checked before anything is sent. Only the aws partition (`amazonaws.com`)
is supported; China and GovCloud endpoints are not.

**Errors.** 429, 5xx and throttling codes (`ThrottlingException`, `Throttling`,
`RequestLimitExceeded`, ...) are retried up to 5 times with exponential
back-off from 1 s, honouring `Retry-After`. Authentication and permission
codes (`UnrecognizedClientException`, `AccessDenied`, `ExpiredToken`, ...)
end the run at once with `aws.ErrAuth`. Error texts carry the operation,
status and AWS error code only.

## Cloudflare

```json
[{"name": "cf-prod", "adapter": "cloudflare",
  "settings": {"zones": "0123456789abcdef0123456789abcdef"},
  "credentials": {"api_token": "cf_ro_ref"}}]
```

| Setting | Meaning |
|---|---|
| `zones` | comma-separated zone IDs; default every zone the token can list. |
| `origin_ca` | `false` skips Origin CA certificates (default `true`). |
| `rate_per_second` | default 4 (Cloudflare's global limit is 1200 requests per 5 minutes per user). |
| `refresh_hours`, `max_pages` | as for AWS. |

**Minimum permissions:** an API token with Zone → Zone → Read and Zone → SSL
and Certificates → Read, scoped to the zones to watch. GET requests only, to
`api.cloudflare.com` only.

**Errors.** 429 and 5xx are retried as for AWS (`Retry-After` up to 5 minutes);
401 and 403 end the run with `cloudflare.ErrAuth`.

## Delta

Neither API offers "changed since". Each adapter keeps, per resource, a
digest of the last observation it sent (`adapter.Cursor`, stored after the
sink took the batch). A sync sends new and changed resources only, and every
resource again each `refresh_hours`. Resources that disappear from the
listing are dropped from the cursor; their absence is the core's signal.

## The proposed contract (0.10.0)

Additive to 0.9.0:

- `Target.kind` gains `cloud_resource`; `Target.cloud` is a `CloudResource`
  (`provider`, `service`, `resource_id` required; `region`, `account`
  optional). Closed (`additionalProperties: false`) because it is target
  identity. Provider-neutral, so Azure and others use the same shape.
- `AdapterEvidence` gains `hostnames`, `bindings` (`Binding`), `renewal`
  (`Renewal`), `cloud_certificate` (`CloudCertificate`) and `endpoint`
  (`Endpoint`), all open objects.
- Rules: method `adapter` only, no `port` or `sni`, `cloud` required (and
  only with this kind), adapter evidence required; `cert_seen` needs
  `served_chain` or `adapter.certificate`; `reached` needs
  `cloud_certificate`, `endpoint` or `bindings`. Rejections use the existing
  `invalid_target`.

`internal/submit/proposed_cloud_test.go` pins the exact field set, checks
the rules against the fake core, and shows that the vendored 0.9.0 contract
rejects `cloud_resource`. `task contract:proposal` runs oasdiff on both
proposals.
