# kubernetes adapter fixtures

All SYNTHETIC, hand-made (WP1.3); nothing here was recorded from a cluster.
The certificates are freshly generated test certificates for
`*.example.test` (public parts only; the keys were discarded). Every
`tls.key` value is either empty or the base64 of the placeholder
`keykeykey...` (low entropy on purpose, so secret scanners do not mistake it
for a key), never key material; `TestFixtureKeysArePlaceholders` enforces
this, inside kubectl last-applied annotations too.

- `cluster/`: the default mode. Two pages of a TLS Secret metadata listing
  (`PartialObjectMetadataList`, continue token, no `data`), cert-manager
  Certificates, Ingresses and Gateways. One Secret carries a kubectl
  last-applied annotation holding the placeholder `tls.key`, as a real
  metadata listing can, to prove it is never decoded.
- `read-secrets/`: `read_tls_crt=true` with namespaces `web,legacy,api`:
  namespaced metadata listings, Certificates and Ingresses, and one `get`
  per named Secret (the only fixtures with `tls.crt`). One Ingress names a
  Secret the metadata listing does not hold.
- `rbac-missing/`: the default RBAC in namespace `web`: the Secret metadata
  listing and the Secret `get` answered 403, Certificates and Ingresses
  readable.
- `optional-missing/`: Secret metadata readable, cert-manager absent (404),
  Ingresses forbidden (403).
- `cluster-ca.b64`: the synthetic CA, base64 of its PEM (no PEM armour is
  committed).

To re-record from a kind or k3d lab cluster running cert-manager: list
`/api/v1/secrets?fieldSelector=type%3Dkubernetes.io%2Ftls&limit=2` with
`Accept: application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1`,
`/apis/cert-manager.io/v1/certificates?limit=2`,
`/apis/networking.k8s.io/v1/ingresses?limit=2` and
`/apis/gateway.networking.k8s.io/v1/gateways?limit=2`, and get single
Secrets only in a lab namespace; then replace every `tls.key` (also inside
annotations) with the placeholder and every host name with
`*.example.test` before committing.
