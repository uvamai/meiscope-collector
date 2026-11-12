# AWS adapter fixtures — SYNTHETIC

**Nothing here was recorded against AWS.** No AWS account was available
(WP1.2). Every exchange is hand-made from the documented request and
response shapes of the AWS API references (ACM JSON 1.1; Elastic Load
Balancing 2015-12-01 and 2012-06-01 and IAM 2010-05-08 Query/XML). Names are
synthetic (`*.example.test`, account `111122223333`, all-zero UUIDs); the
certificates are issued by a throw-away "Synthetic Test CA" whose keys were
deleted after issuing (no key is in the repository). No credentials,
signatures or session tokens appear.

PEM armour in answer bodies is written with JSON `-` escapes, so the
repository-wide no-PEM fixture guard holds literally;
`internal/adapter/cloud` decodes every fixture and requires each PEM block to
be a public `CERTIFICATE`.

| Directory | Contents |
|---|---|
| `synthetic-full/` | Two regions. ap-southeast-2: ACM `ListCertificates` over two pages (`NextToken`), an ACM-issued certificate in use by an ALB and an NLB, and one pending validation; ELBv2 `DescribeLoadBalancers` over two pages (`Marker`), HTTPS and TLS listeners with `DescribeListenerCertificates` (default plus an IAM SNI certificate), an HTTP listener that is skipped; a Classic load balancer with an HTTPS listener on an IAM certificate. us-east-1: an imported ACM certificate used by CloudFront, no load balancers. IAM `ListServerCertificates` over two pages (`IsTruncated`/`Marker`) and `GetServerCertificate`. |
| `synthetic-auth-failure/` | ACM answering 400 `UnrecognizedClientException`; IAM answering 403 `AccessDenied`. |

Throttling (`ThrottlingException`, 429 with `Retry-After`) is injected by the
tests in front of `synthetic-full`.

## To re-record against a test account

Record with a read-only role (policy in docs/cloud-adapters.md), redact
account IDs, ARNs' resource IDs, DNS names and request IDs, then compare the
shapes with these files:

1. ACM `ListCertificates` with `Includes.keyTypes` (confirm that the key-type
   filter is needed to list ECDSA certificates), `DescribeCertificate` for an
   AMAZON_ISSUED (eligible, in use), a PENDING_VALIDATION, an IMPORTED and a
   PRIVATE certificate, and `GetCertificate`; confirm the epoch-second times.
2. ELBv2 `DescribeLoadBalancers`, `DescribeListeners`,
   `DescribeListenerCertificates` (ALB with SNI certificates, NLB TLS) and a
   paginated answer (`NextMarker`).
3. Classic ELB `DescribeLoadBalancers` with HTTPS and SSL listeners.
4. IAM `ListServerCertificates` (truncated) and `GetServerCertificate`.
5. Real error bodies: `ThrottlingException` (JSON), `Throttling` (XML),
   `UnrecognizedClientException`, `AccessDenied`, `ExpiredToken`.
