# kubernetes adapter fixtures

All SYNTHETIC, hand-made (WP1.3); nothing here was recorded from a cluster.

- `cluster/`: two pages of a TLS Secret list (continue token), cert-manager
  Certificates, Ingresses and Gateways. The certificates are freshly
  generated test certificates for `*.example.test` (public parts only; the
  keys were discarded). Every `tls.key` value is the base64 of the
  placeholder `keykeykey...` (low entropy on purpose, so secret scanners do not mistake it for a key), never key material; one Secret
  carries a kubectl last-applied annotation holding that placeholder to
  prove it is never decoded.
- `rbac-missing/`: a namespaced Secret list answered 403.
- `optional-missing/`: Secrets readable, cert-manager absent (404),
  Ingresses forbidden (403).
- `cluster-ca.b64`: the synthetic CA, base64 of its PEM (no PEM armour is
  committed).

To re-record: list `/api/v1/secrets?fieldSelector=type%3Dkubernetes.io%2Ftls&limit=2`,
`/apis/cert-manager.io/v1/certificates?limit=2`,
`/apis/networking.k8s.io/v1/ingresses?limit=2` and
`/apis/gateway.networking.k8s.io/v1/gateways?limit=2` from a kind or k3d
lab cluster running cert-manager, then replace every `tls.key` with the
placeholder and every host name with `*.example.test` before committing.
