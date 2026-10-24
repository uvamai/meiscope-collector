#!/bin/sh
# Runs inside the osquery container (see record-linux.sh). It builds a few
# synthetic files, runs the pack's posix queries through osqueryi and through
# osqueryd's filesystem logger, and leaves the results in /out.
# Throw-away keys are created and deleted here; they never leave the container.
set -e
mkdir -p /opt/app /etc/app /opt/containerd/x /out/log /usr/local/share/ca-certificates
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem \
  -out /usr/local/share/ca-certificates/meiscope-test-ca.crt -days 400 \
  -subj "/CN=Meiscope Test Root CA/O=Example Test" -addext basicConstraints=critical,CA:TRUE 2>/dev/null
update-ca-certificates >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout k2.pem -out /etc/app/tls.pem -days 90 \
  -subj "/CN=app01.example.test" 2>/dev/null
openssl pkcs12 -export -in /etc/app/tls.pem -inkey k2.pem -out /opt/app/keystore.p12 -passout pass:synthetic 2>/dev/null
head -c 3000 /dev/urandom > /opt/app/trust.jks
cp /etc/app/tls.pem /opt/containerd/x/excluded.pem
head -c 20000000 /dev/zero > /opt/app/too-big.pfx
rm -f k.pem k2.pem
sed 's/86400/3/' /pack/meiscope.conf > /tmp/pack.conf
printf '{"options":{"host_identifier":"hostname"},"packs":{"meiscope":"/tmp/pack.conf"}}' > /tmp/osquery.conf
for q in meiscope_certificates_posix meiscope_keystores_posix meiscope_keystore_counts_posix; do
  osqueryi --json "$(cat /pack/$q.sql)" > /out/direct-$q.json 2>/dev/null
done
timeout 5 osqueryd --config_path=/tmp/osquery.conf --logger_plugin=filesystem --logger_path=/out/log \
  --database_path=/tmp/db --pidfile=/tmp/pid --disable_watchdog --host_identifier=hostname >/dev/null 2>&1 || true
ls -la /out/log
