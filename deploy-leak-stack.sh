#!/usr/bin/env bash
###############################################################################
# LEAK Stack Deployment Script
# Target OS : Rocky Linux 9.x
# Stack     : Elasticsearch 8.13.x, Kibana 8.13.x, Logstash 8.13.x, Arkime 5.x
###############################################################################
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ LEAK Stack Deployment Script                                                 ║"
echo "║ Target OS : Rocky Linux 9.x                                                  ║"
echo "║ Stack     : Elasticsearch 8.13.x, Kibana 8.13.x, Logstash 8.13.x, Arkime 5.x ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
set -euo pipefail

ELASTIC_VERSION="8.13.4"
ARKIME_VERSION="6.1.1"

LOG_FILE="/var/log/leak-stack-deploy.log"
CERT_DIR="/etc/elasticsearch/certs"
BACKUP_DIR="/root/leak-backups-$(date +%F-%H%M)"

SYSCTL_FILE="/etc/sysctl.d/99-leak.conf"
LIMITS_FILE="/etc/security/limits.d/99-leak.conf"

# Elasticsearch auto-generates these during package install.
# We now reference them directly instead of generating our own. Smooth criminal.
ES_HTTP_CA="/etc/elasticsearch/certs/http_ca.crt"
ES_HTTP_KEYSTORE="/etc/elasticsearch/certs/http.p12"
ES_TRANSPORT_KEYSTORE="/etc/elasticsearch/certs/transport.p12"

exec > >(tee -a "$LOG_FILE") 2>&1
trap 'echo "[ERROR] Deployment failed at line $LINENO"; exit 1' ERR

require_root() {
  [[ $EUID -eq 0 ]] || { echo "Must run as root"; exit 1; }
}

wait_for_url() {
  local count=1
  local url="$1"
  local ca="$2"
  local auth="$3"
  local tries=60

  echo "Waiting for url: (${url}) - (${count})."
  for i in $(seq 1 "$tries"); do
    if curl -sS --cacert "$ca" -u "$auth" "$url" >/dev/null 2>&1; then
      return 0
    fi
    count+=1
    sleep 5
  done

  echo "Timed out waiting for $url"
  return 1
}

backup_if_exists() {
  local file="$1"
  if [[ -f "$file" ]]; then
    echo "  - Copying (${file}) to (${BACKUP_DIR})"
    cp -a "$file" "$BACKUP_DIR"/
    echo "  Complete!"
  fi
  return 0
}

prompt_secret_confirmed() {
  local prompt="$1"
  local pass1 pass2

  while true; do
    read -rsp "$prompt: " pass1 < /dev/tty
    echo >&2
    read -rsp "Confirm $prompt: " pass2 < /dev/tty
    echo >&2

    if [[ "$pass1" == "$pass2" && ${#pass1} -ge 6 ]]; then
      break
    fi

    echo "Passwords do not match or are shorter than 6 characters" >&2
  done

  printf '%s' "$pass1"
}

require_root

OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
OS_VER=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

if [[ "$OS_ID" != "rocky" || ! "$OS_VER" =~ ^9(\.|$) ]]; then
  echo "Unsupported OS: $OS_ID $OS_VER. Requires Rocky Linux 9.x."
  exit 1
fi

mkdir -p "$BACKUP_DIR"

read -rp "Organization / Domain Name: " ORG_NAME
read -rp "Server Hostname / FQDN: " LEAK_HOSTNAME
read -rp "Timezone [America/Denver]: " TIMEZONE
TIMEZONE=${TIMEZONE:-America/Denver}

interfaces=$(ls /sys/class/net | tr '\n' ' ')
read -rp "Primary Arkime Interface (${interfaces}): " ARK_IFACE

read -rp "Arkime PCAP Storage Path [/data/pcap]: " PCAP_PATH
PCAP_PATH=${PCAP_PATH:-/data/pcap}

read -rp "Retention Period (days) [30]: " RETENTION_DAYS
RETENTION_DAYS=${RETENTION_DAYS:-30}

read -rp "Elasticsearch Heap Size [4g]: " ES_HEAP
# Set a default heap size of 4G if none entered.
ES_HEAP=${ES_HEAP:-4g}
if [[ ! "$ES_HEAP" =~ ^[0-9]+[gGmM]$ ]]; then
  echo "Invalid heap size: $ES_HEAP. Use values like 2g, 4g, or 512m."
  exit 1
fi

KIBANA_PUBLIC_DEFAULT="https://$(echo "${LEAK_HOSTNAME}.${ORG_NAME}" | tr '[:upper:]' '[:lower:]'):5601"
read -rp "Kibana Public Base URL [${KIBANA_PUBLIC_DEFAULT}]: " KIBANA_PUBLIC
KIBANA_PUBLIC=${KIBANA_PUBLIC:-$KIBANA_PUBLIC_DEFAULT}

read -rp "Allowed source CIDR for web access [current subnet or admin IP recommended]: " ALLOWED_CIDR

read -rp "Admin Username: " ADMIN_USER
ADMIN_PASS=$(prompt_secret_confirmed "Admin Password")

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Preparing OS                                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
hostnamectl set-hostname "$LEAK_HOSTNAME"
timedatectl set-timezone "$TIMEZONE"

dnf -y update
dnf -y install epel-release curl wget git java-17-openjdk \
  policycoreutils-python-utils firewalld ncurses unzip tar openssl

systemctl enable --now firewalld

echo "[INFO] Applying kernel and limits settings"
cat > "$SYSCTL_FILE" <<EOF
vm.max_map_count=262144
net.core.rmem_max=134217728
net.core.wmem_max=134217728
EOF

cat > "$LIMITS_FILE" <<EOF
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
arkime soft nofile 65536
arkime hard nofile 65536
EOF

sysctl --system

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Installing Elasticsearch                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

cat > /etc/yum.repos.d/elastic.repo <<EOF
[elastic-8.x]
name=Elastic repository
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
enabled=1
autorefresh=1
type=rpm-md
EOF

dnf -y install "elasticsearch-$ELASTIC_VERSION"

# /etc/elasticsearch/certs inherits the correct SELinux context from
# /etc/elasticsearch (etc_t), so no explicit fcontext rule is needed.
restorecon -R "$CERT_DIR" 2>/dev/null || true

# Continue with the Elastic config and install
backup_if_exists /etc/elasticsearch/elasticsearch.yml
backup_if_exists /etc/elasticsearch/jvm.options

# Elasticsearch installs its own cert directory at /etc/elasticsearch/certs
# with correct ownership and permissions — no manual fixup required.
# Removed cert creation.

cat > /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: leak-cluster
node.name: ${LEAK_HOSTNAME}
network.host: 0.0.0.0
discovery.type: single-node

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# HTTP layer — uses the auto-generated PKCS12 keystore.
# The keystore password is stored in the Elasticsearch secure keystore
# under xpack.security.http.ssl.keystore.secure_password.
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: ${ES_HTTP_KEYSTORE}

# Transport layer (inter-node, even on a single-node cluster) — same idea.
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: ${ES_TRANSPORT_KEYSTORE}
xpack.security.transport.ssl.truststore.path: ${ES_TRANSPORT_KEYSTORE}
EOF

cat > /etc/elasticsearch/jvm.options.d/leak.options <<EOF
-Xms${ES_HEAP}
-Xmx${ES_HEAP}
EOF

systemctl daemon-reload
systemctl enable --now elasticsearch

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Waiting for Elasticsearch to come up                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
# Poll the unauthenticated TLS endpoint; a 401 means ES is up and security is on.
for i in $(seq 1 60); do
  code=$(curl -sS --cacert "$ES_HTTP_CA" -o /dev/null -w "%{http_code}" \
    "https://localhost:9200" || true)
  if [[ "$code" == "401" || "$code" == "200" ]]; then
    break
  fi
  sleep 5
done
if [[ "$code" != "401" && "$code" != "200" ]]; then
  echo "[ERROR] Elasticsearch did not become reachable. Check: journalctl -u elasticsearch -n 200"
  exit 1
fi

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Setting elastic user password                                         ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
# -b: batch mode (skip the y/N "are you sure?" confirmation)
# -i: interactive — read new password from stdin (twice: enter + confirm)
# Drop -s so we can see what the tool is actually doing if it fails.
printf "%s\n%s\n" "$ADMIN_PASS" "$ADMIN_PASS" | \
  /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i -b --url "https://localhost:9200"

wait_for_url "https://localhost:9200/_cluster/health" "$ES_HTTP_CA" "elastic:$ADMIN_PASS"

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Creating ILM policy for Logstash retention                            ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" \
  -H "Content-Type: application/json" \
  -X PUT "https://localhost:9200/_ilm/policy/leak-logstash-retention" \
  -d "{
    \"policy\": {
      \"phases\": {
        \"hot\": {
          \"actions\": {}
        },
        \"delete\": {
          \"min_age\": \"${RETENTION_DAYS}d\",
          \"actions\": {
            \"delete\": {}
          }
        }
      }
    }
  }"

curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" \
  -H "Content-Type: application/json" \
  -X PUT "https://localhost:9200/_index_template/leak-logstash-template" \
  -d "{
    \"index_patterns\": [\"logstash-*\"],
    \"template\": {
      \"settings\": {
        \"index.lifecycle.name\": \"leak-logstash-retention\"
      }
    }
  }"

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Creating index template for Zeek logs                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" \
  -H "Content-Type: application/json" \
  -X PUT "https://localhost:9200/_index_template/leak-zeek-template" \
  -d "{
    \"index_patterns\": [\"zeek-*\"],
    \"template\": {
      \"settings\": {
        \"index.lifecycle.name\": \"leak-logstash-retention\",
        \"number_of_shards\": 1,
        \"number_of_replicas\": 0
      }
    }
  }"

echo "[INFO] Installing Kibana"
dnf -y install "kibana-$ELASTIC_VERSION"
backup_if_exists /etc/kibana/kibana.yml

# Sanity-check that the elastic password actually works before doing anything.
# If reset-password silently failed, we want to know HERE, not later.
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Verifying elastic credentials                                         ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

AUTH_CHECK=$(curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" \
  -o /dev/null -w "%{http_code}" "https://localhost:9200/_security/_authenticate" || echo "000")
if [[ "$AUTH_CHECK" != "200" ]]; then
  echo "[ERROR] Cannot authenticate to Elasticsearch as 'elastic' (HTTP $AUTH_CHECK)"
  echo "        The password reset on line ~226 likely did not take effect."
  echo "        Try manually: /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i"
  exit 1
fi

# Delete any pre-existing token of the same name. Returns 404 on first run
# (which is fine) or 200 on a re-run where the token already exists. This is
# what makes this section idempotent across script reruns.
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Removing any prior Kibana service token                               ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" \
  -X DELETE "https://localhost:9200/_security/service/elastic/kibana/credential/token/leak-kibana-token" \
  >/dev/null || true

# Create the token. Capture the full response so we can show it on failure.
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Creating Kibana service account token                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

KIBANA_TOKEN_RESPONSE=$(curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" \
  -X POST "https://localhost:9200/_security/service/elastic/kibana/credential/token/leak-kibana-token")

# Prefer jq if available; fall back to sed.
if command -v jq >/dev/null 2>&1; then
  KIBANA_TOKEN=$(echo "$KIBANA_TOKEN_RESPONSE" | jq -r '.token.value // empty')
else
  KIBANA_TOKEN=$(echo "$KIBANA_TOKEN_RESPONSE" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
fi

if [[ -z "$KIBANA_TOKEN" ]]; then
  echo "[ERROR] Failed to create Kibana service account token."
  echo "        ES response was:"
  echo "$KIBANA_TOKEN_RESPONSE"
  exit 1
fi

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Kibana token obtained (length: ${#KIBANA_TOKEN} chars)                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

cat > /etc/kibana/kibana.yml <<EOF
server.host: "0.0.0.0"
server.publicBaseUrl: "${KIBANA_PUBLIC}"

elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.serviceAccountToken: "${KIBANA_TOKEN}"
elasticsearch.ssl.certificateAuthorities: ["${ES_HTTP_CA}"]
EOF

chown root:kibana /etc/kibana/kibana.yml
chmod 640 /etc/kibana/kibana.yml

systemctl enable --now kibana

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Installing Logstash                                                   ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
dnf -y install "logstash-$ELASTIC_VERSION"

mkdir -p /etc/logstash/certs
cp "$ES_HTTP_CA" /etc/logstash/certs/elastic-http-ca.crt
chown -R root:logstash /etc/logstash/certs
chmod 640 /etc/logstash/certs/elastic-http-ca.crt

# Suppress the y/N keystore-password prompt by piping 'y'. The || true
# keeps re-runs idempotent (the create command errors if the keystore exists).
echo y | /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create || true
# logstash-keystore add reads from stdin via --stdin and overwrites existing keys silently.
printf "%s" "$ADMIN_PASS" | \
  /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add ES_PWD --stdin

cat > /etc/logstash/conf.d/leak.conf <<EOF
input {
  beats {
    port => 5044
  }

  tcp {
    port => 5140
    type => "syslog"
  }

  udp {
    port => 5140
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGBASE} %{GREEDYDATA:msg}" }
    }
  }
}

output {
  if [type] != "zeek" {
    elasticsearch {
      hosts => ["https://localhost:9200"]
      user => "elastic"
      password => "\${ES_PWD}"
      ssl_enabled => true
      ssl_certificate_authorities => ["/etc/logstash/certs/elastic-http-ca.crt"]
      index => "logstash-%{+YYYY.MM.dd}"
    }
  }
}
EOF

chown root:logstash /etc/logstash/conf.d/leak.conf
chmod 640 /etc/logstash/conf.d/leak.conf

cat > /etc/logstash/conf.d/zeek.conf <<'EOF'
input {
  file {
    path           => "/opt/zeek/logs/current/*.log"
    start_position => "beginning"
    sincedb_path   => "/var/lib/logstash/sincedb_zeek"
    codec          => "json"
    type           => "zeek"
    mode           => "tail"
  }
}

filter {
  if [type] == "zeek" {
    # Zeek emits epoch-seconds in 'ts' — promote it to @timestamp
    date {
      match  => [ "ts", "UNIX" ]
      target => "@timestamp"
    }
    # Tag each event with the Zeek log it came from (conn, dns, http, ssl, ...)
    grok {
      match => { "path" => "/(?<zeek_log_type>[^/]+)\.log$" }
    }
  }
}

output {
  if [type] == "zeek" {
    elasticsearch {
      hosts                       => ["https://localhost:9200"]
      user                        => "elastic"
      password                    => "${ES_PWD}"
      ssl_enabled                 => true
      ssl_certificate_authorities => ["/etc/logstash/certs/elastic-http-ca.crt"]
      index                       => "zeek-%{+YYYY.MM.dd}"
    }
  }
}
EOF

chown root:logstash /etc/logstash/conf.d/zeek.conf
chmod 640 /etc/logstash/conf.d/zeek.conf

systemctl enable --now logstash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Installing Arkime                                                     ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
mkdir -p "$PCAP_PATH"
dnf -y install "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/arkime-${ARKIME_VERSION}-1.el9.x86_64.rpm"

# --- Arkime: things the RPM doesn't do for us -------------------------------
# The Arkime RPM ships only the binaries. The Configure helper script (which
# we don't run because it's interactive) is what normally creates the system
# user, installs the systemd units, and seeds config.ini. We do it explicitly.

# 1. Create the arkime system user/group (idempotent).
if ! getent group arkime >/dev/null; then
  groupadd --system arkime
fi
if ! getent passwd arkime >/dev/null; then
  useradd --system --no-create-home --gid arkime \
    --home-dir /opt/arkime --shell /sbin/nologin arkime
fi

# 2. Seed config.ini from the shipped sample if it isn't there yet.
if [[ ! -f /opt/arkime/etc/config.ini ]]; then
  cp /opt/arkime/etc/config.ini.sample /opt/arkime/etc/config.ini
  chown arkime:arkime /opt/arkime/etc/config.ini
  chmod 640 /opt/arkime/etc/config.ini
fi

# 3. Make sure /opt/arkime is owned by the arkime user end-to-end so the
#    viewer (which runs as 'arkime') can read what it needs.
chown -R arkime:arkime /opt/arkime

# 4. Install systemd units. arkimecapture needs root for AF_PACKET / raw
#    socket access; arkimeviewer can drop privileges to the arkime user.
cat > /etc/systemd/system/arkimecapture.service <<'EOF'
[Unit]
Description=Arkime Capture
After=network-online.target elasticsearch.service
Wants=network-online.target
Requires=elasticsearch.service

[Service]
Type=simple
ExecStart=/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini
WorkingDirectory=/opt/arkime
User=root
Restart=on-failure
RestartSec=10s
LimitMEMLOCK=infinity
LimitCORE=infinity
LimitNOFILE=128000

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/arkimeviewer.service <<'EOF'
[Unit]
Description=Arkime Viewer
After=network-online.target elasticsearch.service arkimecapture.service
Wants=network-online.target
Requires=elasticsearch.service

[Service]
Type=simple
ExecStart=/opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini
WorkingDirectory=/opt/arkime/viewer
User=arkime
Group=arkime
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Generate the Arkime password secret (used to encrypt stored creds in ES)
# and the ES basic-auth string. ARKIME_BASIC_AUTH is plain 'user:pass' —
# Arkime base64-encodes it itself when forming the Authorization header.
ARKIME_SECRET=$(openssl rand -hex 32)
ARKIME_BASIC_AUTH="elastic:${ADMIN_PASS}"

echo "- Check backup_if_exists()"
backup_if_exists /opt/arkime/etc/config.ini

# Arkime viewer runs HTTP on 8005 — front it with a reverse proxy if you need TLS.
grep -q '^viewPort=' /opt/arkime/etc/config.ini \
  && sed -i "s|^viewPort=.*|viewPort=8005|" /opt/arkime/etc/config.ini \
  || echo "viewPort=8005" >> /opt/arkime/etc/config.ini

# Required: Arkime uses this to encrypt user passwords/keys stored in ES.
grep -q '^passwordSecret=' /opt/arkime/etc/config.ini \
  && sed -i "s|^passwordSecret=.*|passwordSecret=${ARKIME_SECRET}|" /opt/arkime/etc/config.ini \
  || echo "passwordSecret=${ARKIME_SECRET}" >> /opt/arkime/etc/config.ini

# Capture interface and PCAP path.
grep -q '^interface=' /opt/arkime/etc/config.ini \
  && sed -i "s|^interface=.*|interface=${ARK_IFACE}|" /opt/arkime/etc/config.ini \
  || echo "interface=${ARK_IFACE}" >> /opt/arkime/etc/config.ini

grep -q '^pcapDir=' /opt/arkime/etc/config.ini \
  && sed -i "s|^pcapDir=.*|pcapDir=${PCAP_PATH}|" /opt/arkime/etc/config.ini \
  || echo "pcapDir=${PCAP_PATH}" >> /opt/arkime/etc/config.ini

grep -q '^elasticsearch=' /opt/arkime/etc/config.ini \
  && sed -i "s|^elasticsearch=.*|elasticsearch=https://localhost:9200|" /opt/arkime/etc/config.ini \
  || echo "elasticsearch=https://localhost:9200" >> /opt/arkime/etc/config.ini

# Make sure no stale httpsPort/keyFile/certFile lines remain from package defaults.
sed -i \
  -e 's/^httpsPort=.*/#httpsPort=/' \
  -e 's|^keyFile=.*|#keyFile=|' \
  -e 's|^certFile=.*|#certFile=|' \
  /opt/arkime/etc/config.ini

grep -q '^caTrustFile=' /opt/arkime/etc/config.ini \
  && sed -i "s|^caTrustFile=.*|caTrustFile=${ES_HTTP_CA}|" /opt/arkime/etc/config.ini \
  || echo "caTrustFile=${ES_HTTP_CA}" >> /opt/arkime/etc/config.ini

grep -q '^elasticsearchBasicAuth=' /opt/arkime/etc/config.ini \
  && sed -i "s|^elasticsearchBasicAuth=.*|elasticsearchBasicAuth=${ARKIME_BASIC_AUTH}|" /opt/arkime/etc/config.ini \
  || echo "elasticsearchBasicAuth=${ARKIME_BASIC_AUTH}" >> /opt/arkime/etc/config.ini

grep -q '^usersElasticsearch=' /opt/arkime/etc/config.ini \
  && sed -i "s|^usersElasticsearch=.*|usersElasticsearch=https://localhost:9200|" /opt/arkime/etc/config.ini \
  || echo "usersElasticsearch=https://localhost:9200" >> /opt/arkime/etc/config.ini

grep -q '^usersElasticsearchBasicAuth=' /opt/arkime/etc/config.ini \
  && sed -i "s|^usersElasticsearchBasicAuth=.*|usersElasticsearchBasicAuth=${ARKIME_BASIC_AUTH}|" /opt/arkime/etc/config.ini \
  || echo "usersElasticsearchBasicAuth=${ARKIME_BASIC_AUTH}" >> /opt/arkime/etc/config.ini

grep -q '^authMode=' /opt/arkime/etc/config.ini \
  && sed -i "s/^authMode=.*/authMode=digest/" /opt/arkime/etc/config.ini \
  || echo "authMode=digest" >> /opt/arkime/etc/config.ini

grep -q '^rotateIndex=' /opt/arkime/etc/config.ini \
  && sed -i "s/^rotateIndex=.*/rotateIndex=daily/" /opt/arkime/etc/config.ini \
  || echo "rotateIndex=daily" >> /opt/arkime/etc/config.ini


chown -R arkime:arkime "$PCAP_PATH" 2>/dev/null || true

if [[ -x /opt/arkime/db/db.pl ]]; then
  /opt/arkime/db/db.pl --insecure --esuser elastic --espass "$ADMIN_PASS" https://localhost:9200 init
fi

/opt/arkime/bin/arkime_add_user.sh \
  "$ADMIN_USER" "$ORG_NAME Admin" "$ADMIN_PASS" --admin

systemctl enable --now arkimecapture arkimeviewer

###############################################################################
# Zeek Network Security Monitor (LTS)
# Shares the same monitor interface as Arkime — both use AF_PACKET so the
# kernel hands a copy of each frame to each daemon. No conflict.
###############################################################################
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Installing Zeek (LTS)                                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

# --- NIC offload disable -----------------------------------------------------
# Hardware offloads mangle frame boundaries before they reach userspace, which
# breaks both Zeek's and Arkime's view of the wire. Disable them persistently
# via a templated systemd unit keyed on the interface name.
cat > /etc/systemd/system/disable-nic-offload@.service <<'EOF'
[Unit]
Description=Disable NIC offloads on %i for accurate packet capture
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ethtool -K %i rx off tx off sg off tso off gso off gro off lro off
ExecStart=/usr/sbin/ip link set dev %i promisc on

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "disable-nic-offload@${ARK_IFACE}.service"

# --- Repository + install ----------------------------------------------------
curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/RHEL_9/security:zeek.repo" \
  -o /etc/yum.repos.d/zeek.repo

dnf -y install zeek-lts

# Make /opt/zeek/bin globally available for interactive use
cat > /etc/profile.d/zeek.sh <<'EOF'
export PATH="$PATH:/opt/zeek/bin"
EOF

# --- Configuration -----------------------------------------------------------
backup_if_exists /opt/zeek/etc/node.cfg
backup_if_exists /opt/zeek/etc/networks.cfg
backup_if_exists /opt/zeek/etc/zeekctl.cfg
backup_if_exists /opt/zeek/share/zeek/site/local.zeek

# Single-node standalone — matches your single-node ES deployment
cat > /opt/zeek/etc/node.cfg <<EOF
[zeek]
type=standalone
host=localhost
interface=${ARK_IFACE}
EOF

# RFC1918 space treated as local; adjust for your environment as needed
cat > /opt/zeek/etc/networks.cfg <<'EOF'
10.0.0.0/8       Private IP space
172.16.0.0/12    Private IP space
192.168.0.0/16   Private IP space
EOF

# Log rotation aligned with the script's RETENTION_DAYS prompt
cat > /opt/zeek/etc/zeekctl.cfg <<EOF
LogRotationInterval = 3600
LogExpireInterval = ${RETENTION_DAYS}day
StatsLogExpireInterval = ${RETENTION_DAYS}day
MailTo = root@localhost
SendMail =
LogDir = /opt/zeek/logs
SpoolDir = /opt/zeek/spool
CompressLogs = 1
EOF

# Site policy — emit JSON so Logstash can ingest with the json codec
cat > /opt/zeek/share/zeek/site/local.zeek <<'EOF'
@load policy/tuning/json-logs.zeek
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/validate-certs
@load frameworks/files/hash-all-files
EOF

# --- systemd service ---------------------------------------------------------
# zeekctl deploy = check + install + stop + start (canonical start path)
cat > /etc/systemd/system/zeek.service <<EOF
[Unit]
Description=Zeek Network Security Monitor
After=network-online.target disable-nic-offload@${ARK_IFACE}.service
Wants=network-online.target
Requires=disable-nic-offload@${ARK_IFACE}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/opt/zeek/bin/zeekctl install
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl restart

[Install]
WantedBy=multi-user.target
EOF

# Periodic health check — restarts crashed nodes, prunes old logs
cat > /etc/systemd/system/zeekctl-cron.service <<'EOF'
[Unit]
Description=Zeek health check (zeekctl cron)
After=zeek.service
Requires=zeek.service

[Service]
Type=oneshot
ExecStart=/opt/zeek/bin/zeekctl cron
EOF

cat > /etc/systemd/system/zeekctl-cron.timer <<'EOF'
[Unit]
Description=Run zeekctl cron every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Unit=zeekctl-cron.service

[Install]
WantedBy=timers.target
EOF

# Logstash needs to read Zeek's current logs
chmod 755 /opt/zeek /opt/zeek/logs
mkdir -p /opt/zeek/logs/current
chmod 755 /opt/zeek/logs/current

systemctl daemon-reload
systemctl enable --now zeek.service
systemctl enable --now zeekctl-cron.timer

# Brief readiness check — non-fatal so deploy can continue
sleep 5
/opt/zeek/bin/zeekctl status || \
  echo "[WARN] Zeek not yet healthy. Run: /opt/zeek/bin/zeekctl diag"

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Configuring firewall                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
#firewall-cmd --permanent --remove-port=9200/tcp || true
firewall-cmd --permanent --remove-port=5601/tcp || true
firewall-cmd --permanent --remove-port=8005/tcp || true
firewall-cmd --permanent --remove-port=5044/tcp || true
firewall-cmd --permanent --remove-port=5140/tcp || true
firewall-cmd --permanent --remove-port=5140/udp || true

firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ALLOWED_CIDR} port protocol=tcp port=5601 accept"
firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ALLOWED_CIDR} port protocol=tcp port=8005 accept"
firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ALLOWED_CIDR} port protocol=tcp port=5044 accept"
firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ALLOWED_CIDR} port protocol=tcp port=5140 accept"
firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ALLOWED_CIDR} port protocol=udp port=5140 accept"

firewall-cmd --reload

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ [INFO] Validating services                                                   ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
systemctl is-active --quiet elasticsearch
systemctl is-active --quiet kibana
systemctl is-active --quiet logstash
systemctl is-active --quiet arkimeviewer
systemctl is-active --quiet arkimecapture
systemctl is-active --quiet zeek

curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" "https://localhost:9200/_cluster/health?pretty"

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ ╔══════════════════════════════════════════════════════════════════════════╗ ║"
echo "║ ║ LEAK STACK DEPLOYMENT COMPLETE                                           ║ ║"
echo "║ ╚══════════════════════════════════════════════════════════════════════════╝ ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

echo "Elasticsearch : https://${LEAK_HOSTNAME}:9200"
echo "Kibana        : ${KIBANA_PUBLIC}"
echo "Arkime        : https://${LEAK_HOSTNAME}:8005"
echo "Zeek          : standalone on ${ARK_IFACE}  (logs: /opt/zeek/logs/current/)"
echo "Admin User    : ${ADMIN_USER}"
echo "Retention     : ${RETENTION_DAYS} days for logstash-* and zeek-* via ILM"
echo "Backups       : ${BACKUP_DIR}"
echo "TLS CA        : ${ES_HTTP_CA}"
echo
echo "Zeek troubleshooting:"
echo "  /opt/zeek/bin/zeekctl status"
echo "  /opt/zeek/bin/zeekctl diag"
echo "  journalctl -u zeek -n 100"
echo "  ls -la /opt/zeek/logs/current/"
echo
systemctl status elasticsearch kibana logstash arkimeviewer arkimecapture zeek --no-pager

