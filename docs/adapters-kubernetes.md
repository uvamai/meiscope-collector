# Kubernetes adapter

Adapter name `kubernetes`, evidence source `kubernetes` (FR-DISC-027,
WP1.3). By default it reads **no Secret data**. Through the Kubernetes API,
with read-only permissions, it reads:

- **Ingresses** (`networking.k8s.io/v1`) and, with `gateway_api=true`,
  **Gateways** (`gateway.networking.k8s.io/v1`): the TLS sections, which
  name the Secrets that serve TLS and bind host names to them
  (`kubernetes.hostnames`, `kubernetes.references`). Cross-namespace
  Gateway references are recorded as written; the adapter does not evaluate
  ReferenceGrants.
- **cert-manager Certificates** (`certificates.cert-manager.io/v1`):
  name, `issuerRef`, `dnsNames`, the Ready condition, `notAfter`,
  `renewalTime` and `revision`, attached to the Secret named by
  `spec.secretName`. A Secret that cert-manager owns gets
  `renewal_mode: external_automated`, and `cert_manager.not_after` carries
  its expiry without the Secret being read.
- **TLS Secret metadata**, only where the operator grants `list` on
  Secrets (the default RBAC below does not): the listing asks for
  `Accept: application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1`
  with the field selector `type=kubernetes.io/tls`, so the API server
  returns names and annotations, no `data`. A response that is not a
  `PartialObjectMetadataList` is refused and not used. Of the annotations
  the adapter decodes only the three `cert-manager.io/*` names; kubectl's
  `last-applied-configuration` (which, for a Secret created with
  `kubectl apply`, holds its whole data, `tls.key` included, even in a
  metadata listing) is skipped by the decoder and never copied, and each
  response buffer is zeroed once decoded. With the metadata listing, a
  reference to a Secret it does not hold is counted
  (`reference_without_secret`, `certificate_without_secret`) and not
  reported; without it, every referenced Secret is reported.

Each Secret found becomes one observation: target kind `store`, host the API
server's host name, store `kubernetes/<cluster>/<namespace>/<secret>`,
method `adapter`, outcome `reached`, no `certificate`, and the finding
`secret_not_read` (proposed contract 0.10.0, see Feature switches).

### Opt-in: reading tls.crt (`read_tls_crt=true`)

Only with `read_tls_crt=true` **and** a non-empty `namespaces` allow-list
does the adapter read certificate data, and then only one named Secret at a
time: `GET /api/v1/namespaces/<ns>/secrets/<name>` for each Secret found as
above in an allowed namespace (it never lists Secret data). From each
response it decodes `type` (anything but `kubernetes.io/tls` is skipped,
`skipped_not_tls`), `tls.crt` (parsed for public certificate fields) and
whether `tls.key` is non-empty (`custody.key_custody` `present` or
`absent`); `tls.key` itself is never decoded or copied. A response is at
most 2 MiB and is zeroed as soon as it is decoded. The Secret then gets
outcome `cert_seen` and `adapter.certificate` describing the leaf, which a
0.9.0 core accepts. A 401 or 403 on such a Secret fails the run with
`ErrRBAC`: the operator asked for data the role does not grant.

The setting is called `read_tls_crt`, not `read_tls_secrets`: adapter
setting names may not contain `secret`, `token` or similar words, so that no
credential value is ever put in `settings` (internal/adapter/adapter.go).

The adapter never writes, never watches, never execs, and connects to
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
| `namespaces` | comma-separated; default all namespaces (lets the RBAC be namespaced Roles); required with `read_tls_crt` |
| `read_tls_crt` | default `false`: no Secret data is read. `true` gets each named Secret in `namespaces` and parses `tls.crt` only |
| `page_size` | list `limit`, default 500 |
| `rate_per_second` | default 5 |
| `cert_manager`, `ingress` | default true; `gateway_api` default false |

Credentials: `bearer_token` through `credential.Source`. The pod's
projected service-account token is used only with `in_cluster=true`, no
`bearer_token`, and the in-cluster API server (`api_server` unset,
`https://kubernetes.default.svc` or
`https://kubernetes.default.svc.cluster.local`, port 443). Any other
`api_server` needs an explicit `bearer_token`, so the pod's token is never
sent elsewhere. It is read from
`/var/run/secrets/kubernetes.io/serviceaccount/token` on every sync (it
rotates) and is never copied. The client presents no client certificate and
never follows a redirect (3xx is an error), so the token cannot follow one
to another host.

## Default RBAC (no Secret permission)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: meiscope-reader
rules:
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

Bind it with a ClusterRoleBinding, or per namespace with RoleBindings and
set `namespaces`. It grants nothing on Secrets: the adapter reports the
Secrets that Ingresses, Gateways and cert-manager name. A 401 or 403 on the
Secret metadata listing counts `rbac_missing_secrets`, is logged at info
level and the run continues.

Kubernetes RBAC cannot restrict `list` on Secrets to metadata: a role that
may list Secrets may read their data, whatever the adapter asks for. Grant
`list` on Secrets only where finding Secrets that nothing references is
worth that, and only in a namespaced Role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: meiscope-secret-metadata
  namespace: web
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list"]
```

## Opt-in RBAC (`read_tls_crt=true`)

Per allowed namespace, `get` on Secrets, ideally limited to the named TLS
Secrets with `resourceNames` (the adapter needs no `list` for this; it gets
the Secrets references name):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: meiscope-tls-crt
  namespace: web
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["www-tls"]
  verbs: ["get"]
```

A `get` returns the whole Secret, `tls.key` included, to the collector's
memory; the adapter decodes only `tls.crt` and zeroes the buffer. Never
grant Secret permissions cluster-wide.

Missing permissions: a 403 on Certificates, Ingresses or Gateways counts
`rbac_missing_<resource>` and the run continues without them; a 404 (CRD or
API group not installed) counts `api_absent_<resource>`.

## Pagination, delta and rate limits

Lists use `limit` and `continue`. A continue token the server expired
(410 Gone) restarts that listing once (`continue_expired`). The cursor holds,
per Secret, a fingerprint of the observation last emitted and the Secret
metadata listing's `resourceVersion`; a Secret is sent again only when its
certificate, custody, cert-manager state or bindings changed (`unchanged`,
`removed` count the rest). Calls, including each Secret get with
`read_tls_crt`, are spaced by `rate_per_second`; 429 and 5xx are retried
with `Retry-After` honoured.

## Feature switches

Store observations are sent only with `MEISCOPE_FEATURE_LOCAL_STORE_V1=true`
(the core accepts them only with its own local-store switch on). Off, the
run counts `skipped_feature_disabled` and keeps the old cursor.

A Secret reported without its certificate (the default) is change (4) of
the contract 0.10.0 proposal (`api/proposed/collector-0.10.0-proposed.yaml`):
a 0.9.0 core refuses it, so it is sent only with
`MEISCOPE_FEATURE_ADAPTER_EVIDENCE_V2=true` as well. Off, those Secrets
count `skipped_feature_disabled` and are not recorded in the cursor, so
they are sent once the switch is on. Secrets read with `read_tls_crt` carry
a certificate and need only the local-store switch. The `kubernetes`,
`renewal_mode`, `certificate.sha256` and `certificate.dns_names` fields are
proposed in contract 0.10.0; a 0.9.0 core accepts and ignores them.

## Statistics

`secrets_listed` (metadata), `secrets_not_read`, `secrets_read`,
`secret_not_found`, `skipped_not_tls`, `unchanged`, `removed`,
`skipped_bad_certificate`, `certificate_without_secret`,
`reference_without_secret`, `reference_outside_namespaces`,
`continue_expired`, `skipped_feature_disabled`, `rbac_missing_<resource>`,
`api_absent_<resource>`.
