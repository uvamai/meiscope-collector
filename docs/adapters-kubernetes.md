# Kubernetes adapter

Adapter name `kubernetes`, evidence source `kubernetes` (FR-DISC-027,
WP1.3). It reads, through the Kubernetes API and with read-only
permissions:

- **TLS Secrets** (`type: kubernetes.io/tls`, listed with the field
  selector `type=kubernetes.io/tls`): the certificate chain in `tls.crt`,
  parsed for public certificate fields. Of `tls.key` the adapter only checks
  whether the value is empty; it never decodes it, and reports
  `custody.key_custody` `present` or `absent`. Of the annotations it decodes
  only the `cert-manager.io/*` names; kubectl's
  `last-applied-configuration` (which can hold the whole Secret) is never
  decoded.
- **cert-manager Certificates** (`certificates.cert-manager.io/v1`):
  name, `issuerRef`, `dnsNames`, the Ready condition, `notAfter`,
  `renewalTime` and `revision`, attached to the Secret named by
  `spec.secretName`. A Secret that cert-manager owns gets
  `renewal_mode: external_automated`.
- **Ingresses** (`networking.k8s.io/v1`) and, with `gateway_api=true`,
  **Gateways** (`gateway.networking.k8s.io/v1`): the TLS sections, to bind
  host names to Secrets (`kubernetes.hostnames`, `kubernetes.references`).
  Cross-namespace Gateway references are recorded as written; the adapter
  does not evaluate ReferenceGrants.

Each TLS Secret becomes one observation: target kind `store`, host the API
server's host name, store `kubernetes/<cluster>/<namespace>/<secret>`,
method `adapter`, outcome `cert_seen`, `adapter.certificate` describing the
leaf. The adapter never writes, never watches, never execs, and connects to
nothing but the configured API server.

## Configuration

```json
[{"name": "k8s-prod", "adapter": "kubernetes",
  "settings": {"cluster": "prod", "api_server": "https://k8s.example.test:6443",
               "ca_file": "/etc/meiscope/prod-ca.crt", "gateway_api": "true"},
  "credentials": {"bearer_token": "k8s_prod_reader_token"}}]
```

| Setting | Meaning |
|---|---|
| `cluster` | required; short name used in the store locator |
| `api_server` | https URL; default `https://kubernetes.default.svc` with `in_cluster` |
| `ca_file` / `kubeconfig` (+`kube_context`) / `in_cluster=true` / `system_roots=true` | exactly one trust anchor; the API server certificate is always verified. From a kubeconfig only the cluster's `server` and CA are read, never `users`; `insecure-skip-tls-verify` is refused |
| `namespaces` | comma-separated; default all namespaces (lets the RBAC be namespaced Roles) |
| `page_size` | list `limit`, default 500 |
| `rate_per_second` | default 5 |
| `cert_manager`, `ingress` | default true; `gateway_api` default false |

Credentials: `bearer_token` through `credential.Source`. With
`in_cluster=true` and no `bearer_token`, the pod's projected service-account
token is read from `/var/run/secrets/kubernetes.io/serviceaccount/token` on
every sync (it rotates) and is never copied. The client presents no client
certificate and does not follow redirects.

## Minimal RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: meiscope-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
- apiGroups: ["cert-manager.io"]
  resources: ["certificates"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list"]
- apiGroups: ["gateway.networking.k8s.io"]   # only with gateway_api=true
  resources: ["gateways"]
  verbs: ["get", "list"]
```

Bind it with a ClusterRoleBinding, or bind it per namespace with
RoleBindings and set `namespaces`. Kubernetes RBAC cannot restrict `list`
to Secrets of one type: the role can read every Secret in its scope. The
adapter asks the server for TLS Secrets only (field selector), but the
permission is broader than what it uses; scope it with namespaces where
that matters. A Secret list response carries `tls.key`; the adapter keeps
it only as an undecoded byte slice inside the response it is parsing.

Missing permissions: a 401 or 403 on Secrets fails the run with an error
naming this section (nothing is reported). A 403 on Certificates, Ingresses
or Gateways counts `rbac_missing_<resource>` and the run continues without
them; a 404 (CRD or API group not installed) counts `api_absent_<resource>`.

## Pagination, delta and rate limits

Lists use `limit` and `continue`. A continue token the server expired
(410 Gone) restarts that listing once (`continue_expired`). The cursor holds,
per Secret, a fingerprint of the observation last emitted and the list's
`resourceVersion`; a Secret is sent again only when its certificate,
custody, cert-manager state or bindings changed (`unchanged`, `removed`
count the rest). Calls are spaced by `rate_per_second`; 429 and 5xx are
retried with `Retry-After` honoured.

## Feature switch

Store observations are sent only with `MEISCOPE_FEATURE_LOCAL_STORE_V1=true`
(the core accepts them only with its own local-store switch on). Off, the
run counts `skipped_feature_disabled` and keeps the old cursor. The
`kubernetes`, `renewal_mode`, `certificate.sha256` and
`certificate.dns_names` fields are proposed in contract 0.10.0; a 0.9.0
core accepts and ignores them.

## Statistics

`secrets_listed`, `unchanged`, `removed`, `skipped_bad_certificate`,
`certificate_without_secret`, `continue_expired`,
`skipped_feature_disabled`, `rbac_missing_<resource>`,
`api_absent_<resource>`.
