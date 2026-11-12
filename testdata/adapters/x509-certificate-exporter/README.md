# x509-certificate-exporter fixtures

`metrics.prom` is SYNTHETIC, hand-made from the label set the
x509-certificate-exporter README documents (`filepath`, `issuer_*`,
`subject_*`, `serial_number`, `secret_namespace`, `secret_name`,
`secret_key`). It includes a malformed line and series without serial,
not_after or an absolute path. Re-record from a real exporter (DaemonSet
for host files, Deployment watching Secrets) and replace host names.
