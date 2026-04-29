#!/usr/bin/env bash
###############################################################################
# LEAK Stack Deployment Script
# Target OS : Rocky Linux 9.3
# Stack     : Elasticsearch 8.13.x, Kibana 8.13.x, Logstash 8.13.x, Arkime 5.x
###############################################################################

set -euo pipefail

ELASTIC_VERSION="8.13.4"
ARKIME_VERSION="5.3.0"

LOG_FILE="/var/log/leak-stack-deploy.log"
CERT_DIR="/etc/leak/tls"
BACKUP_DIR="/root/leak-backups-$(date +%F-%H%M)"

SYSCTL_FILE="/etc/sysctl.d/99-leak.conf"
LIMITS_FILE="/etc/security/limits.d/99-leak.conf"

ES_HTTP_CA="$CERT_DIR/elastic-http-ca.crt"
ES_HTTP_KEY="$CERT_DIR/elastic-http.key"
ES_HTTP_CERT="$CERT_DIR/elastic-http.crt"

exec > >(tee -a "$LOG_FILE") 2>&1
trap 'echo "[ERROR] Deployment failed at line $LINENO"; exit 1' ERR

require_root() {
  [[ $EUID -eq 0 ]] || { echo "Must run as root"; exit 1; }
}

wait_for_url() {
  local url="$1"
  local ca="$2"
  local auth="$3"
  local tries=60

  for i in $(seq 1 "$tries"); do
    if curl -sS --cacert "$ca" -u "$auth" "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done

  echo "Timed out waiting for $url"
  return 1
}

backup_if_exists() {
  local file="$1"
  [[ -f "$file" ]] && cp -a "$file" "$BACKUP_DIR"/
}

prompt_secret_confirmed() {
  local prompt="$1"
  local pass1 pass2

  while true; do
    read -rsp "$prompt: " pass1; echo
    read -rsp "Confirm $prompt: " pass2; echo
    [[ "$pass1" == "$pass2" && -n "$pass1" ]] && break
    echo "Passwords do not match or are empty"
  done

  printf '%s' "$pass1"
}

require_root

OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
OS_VER=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

if [[ "$OS_ID" != "rocky" || "$OS_VER" != "9.3" ]]; then
  echo "Unsupported OS: $OS_ID $OS_VER. Requires Rocky Linux 9.3."
  exit 1
fi

mkdir -p "$BACKUP_DIR"

read -rp "Organization / Environment Name: " ORG_NAME
read -rp "Server Hostname / FQDN: " LEAK_HOSTNAME
read -rp "Timezone [America/Denver]: " TIMEZONE
TIMEZONE=${TIMEZONE:-America/Denver}

read -rp "Primary Arkime Interface (example: eno1): " ARK_IFACE
read -rp "Arkime PCAP Storage Path [/data/pcap]: " PCAP_PATH
PCAP_PATH=${PCAP_PATH:-/data/pcap}

read -rp "Retention Period (days) [30]: " RETENTION_DAYS
RETENTION_DAYS=${RETENTION_DAYS:-30}

read -rp "Elasticsearch Heap Size (example: 4g): " ES_HEAP
read -rp "Kibana Public Base URL (example: https://leak.example.com:5601): " KIBANA_PUBLIC
read -rp "Allowed source CIDR for web access [current subnet or admin IP recommended]: " ALLOWED_CIDR

read -rp "Admin Username: " ADMIN_USER
ADMIN_PASS=$(prompt_secret_confirmed "Admin Password")

echo "[INFO] Preparing OS"
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

echo "[INFO] Creating local TLS material"
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

openssl req -x509 -nodes -days 1095 -newkey rsa:4096 \
  -keyout "$ES_HTTP_KEY" \
  -out "$ES_HTTP_CERT" \
  -subj "/CN=$LEAK_HOSTNAME/O=$ORG_NAME" \
  -addext "subjectAltName=DNS:$LEAK_HOSTNAME,DNS:localhost,IP:127.0.0.1"

cp "$ES_HTTP_CERT" "$ES_HTTP_CA"

chown -R root:elasticsearch "$CERT_DIR" 2>/dev/null || true
chmod 640 "$ES_HTTP_KEY"
chmod 644 "$ES_HTTP_CERT" "$ES_HTTP_CA"


echo "[INFO] Installing Elasticsearch"
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

backup_if_exists /etc/elasticsearch/elasticsearch.yml
backup_if_exists /etc/elasticsearch/jvm.options

#chown -R root:elasticsearch "$CERT_DIR"
chown root:elasticsearch "$ES_HTTP_KEY"

cat > /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: leak-cluster
node.name: ${LEAK_HOSTNAME}
network.host: 0.0.0.0
discovery.type: single-node

xpack.security.enabled: true
xpack.security.enrollment.enabled: false

xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: ${ES_HTTP_KEY}
xpack.security.http.ssl.certificate: ${ES_HTTP_CERT}
xpack.security.http.ssl.certificate_authorities: [ "${ES_HTTP_CA}" ]

xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.key: ${ES_HTTP_KEY}
xpack.security.transport.ssl.certificate: ${ES_HTTP_CERT}
xpack.security.transport.ssl.certificate_authorities: [ "${ES_HTTP_CA}" ]
EOF

cat > /etc/elasticsearch/jvm.options.d/leak.options <<EOF
-Xms${ES_HEAP}
-Xmx${ES_HEAP}
EOF

systemctl daemon-reload
systemctl enable --now elasticsearch

echo "[INFO] Setting elastic user password"
sleep 20
printf "%s\n%s\n" "$ADMIN_PASS" "$ADMIN_PASS" | \
  /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i

wait_for_url "https://localhost:9200" "$ES_HTTP_CA" "elastic:$ADMIN_PASS"

echo "[INFO] Creating ILM policy for Logstash retention"
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

echo "[INFO] Installing Kibana"
dnf -y install "kibana-$ELASTIC_VERSION"
backup_if_exists /etc/kibana/kibana.yml

KIBANA_TOKEN=$(/usr/share/elasticsearch/bin/elasticsearch-service-tokens create elastic/kibana leak-kibana-token | awk -F'= ' '{print $2}')

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

echo "[INFO] Installing Logstash"
dnf -y install "logstash-$ELASTIC_VERSION"

mkdir -p /etc/logstash/certs
cp "$ES_HTTP_CA" /etc/logstash/certs/elastic-http-ca.crt
chown -R root:logstash /etc/logstash/certs
chmod 640 /etc/logstash/certs/elastic-http-ca.crt

/usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create || true
printf "%s" "$ADMIN_PASS" | /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add ES_PWD --stdin --force

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
  elasticsearch {
    hosts => ["https://localhost:9200"]
    user => "elastic"
    password => "\${ES_PWD}"
    ssl_enabled => true
    ssl_certificate_authorities => ["/etc/logstash/certs/elastic-http-ca.crt"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
}
EOF

chown root:logstash /etc/logstash/conf.d/leak.conf
chmod 640 /etc/logstash/conf.d/leak.conf

systemctl enable --now logstash

echo "[INFO] Installing Arkime"
mkdir -p "$PCAP_PATH"
dnf -y install "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/arkime_${ARKIME_VERSION}-1.x86_64.rpm"

backup_if_exists /opt/arkime/etc/config.ini

ARKIME_SECRET=$(openssl rand -hex 32)
ARKIME_BASIC_AUTH=$(printf "elastic:%s" "$ADMIN_PASS" | base64 -w0)

sed -i \
  -e "s/^interface=.*/interface=${ARK_IFACE}/" \
  -e "s|^pcapDir=.*|pcapDir=${PCAP_PATH}|" \
  -e "s|^elasticsearch=.*|elasticsearch=https://localhost:9200|" \
  -e "s/^passwordSecret=.*/passwordSecret=${ARKIME_SECRET}/" \
  /opt/arkime/etc/config.ini

for setting in \
  "httpsPort=8005" \
  "keyFile=${ES_HTTP_KEY}" \
  "certFile=${ES_HTTP_CERT}"
do
  grep -q "^${setting%%=*}=" /opt/arkime/etc/config.ini \
    && sed -i "s|^${setting%%=*}=.*|$setting|" /opt/arkime/etc/config.ini \
    || echo "$setting" >> /opt/arkime/etc/config.ini
done

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

echo "[INFO] Configuring firewall"
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

echo "[INFO] Validating services"
systemctl is-active --quiet elasticsearch
systemctl is-active --quiet kibana
systemctl is-active --quiet logstash
systemctl is-active --quiet arkimeviewer
systemctl is-active --quiet arkimecapture

curl -sS --cacert "$ES_HTTP_CA" -u "elastic:$ADMIN_PASS" "https://localhost:9200/_cluster/health?pretty"

echo "================================================="
echo " LEAK STACK DEPLOYMENT COMPLETE"
echo "================================================="
echo "Elasticsearch : https://${LEAK_HOSTNAME}:9200"
echo "Kibana        : ${KIBANA_PUBLIC}"
echo "Arkime        : https://${LEAK_HOSTNAME}:8005"
echo "Admin User    : ${ADMIN_USER}"
echo "Retention     : ${RETENTION_DAYS} days for logstash-* via ILM"
echo "Backups       : ${BACKUP_DIR}"
echo "TLS CA        : ${ES_HTTP_CA}"
echo
systemctl status elasticsearch kibana logstash arkimeviewer arkimecapture --no-pager

