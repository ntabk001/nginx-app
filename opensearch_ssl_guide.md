# OpenSearch Stack with SSL Installation Guide (Tarball Binary)

This guide covers the installation of Logstash, OpenSearch, and OpenSearch Dashboard using tarball binary files with SSL/TLS security configuration.

## Prerequisites

- Ubuntu/Debian or CentOS/RHEL system
- Java 11 or higher
- Root or sudo access
- At least 4GB RAM (8GB recommended)

## Step 1: System Preparation

### Create Users and Directories
```bash
# Create opensearch user
sudo useradd -m -s /bin/bash opensearch

# Create logstash user
sudo useradd -m -s /bin/bash logstash

# Create installation directories
sudo mkdir -p /opt/opensearch
sudo mkdir -p /opt/opensearch-dashboards
sudo mkdir -p /opt/logstash
sudo mkdir -p /var/lib/opensearch
sudo mkdir -p /var/log/opensearch
sudo mkdir -p /var/log/opensearch-dashboards
sudo mkdir -p /var/log/logstash
```

### Update System and Install Java
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y
sudo apt install openjdk-11-jdk wget curl -y

# CentOS/RHEL
sudo yum update -y
sudo yum install java-11-openjdk-devel wget curl -y
```

### Verify Java Installation
```bash
java -version
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64  # Ubuntu/Debian
# export JAVA_HOME=/usr/lib/jvm/java-11-openjdk      # CentOS/RHEL
```

## Step 2: Download and Install OpenSearch

### Download OpenSearch Tarball
```bash
cd /tmp
wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.tar.gz
tar -xzf opensearch-2.11.1-linux-x64.tar.gz
sudo mv opensearch-2.11.1 /opt/opensearch/
sudo ln -sf /opt/opensearch/opensearch-2.11.1 /opt/opensearch/current
```

### Set Ownership and Permissions
```bash
sudo chown -R opensearch:opensearch /opt/opensearch/
sudo chown -R opensearch:opensearch /var/lib/opensearch/
sudo chown -R opensearch:opensearch /var/log/opensearch/
```

## Step 3: Configure SSL Certificates for OpenSearch

### Create SSL Certificate Directory
```bash
sudo mkdir -p /opt/opensearch/current/config/ssl
sudo chown opensearch:opensearch /opt/opensearch/current/config/ssl
```

### Generate Self-Signed Certificates
```bash
# Switch to opensearch user for certificate generation
sudo -u opensearch bash << 'EOF'
cd /opt/opensearch/current/config/ssl

# Generate root CA
openssl genrsa -out root-ca-key.pem 2048
openssl req -new -x509 -sha256 -key root-ca-key.pem -out root-ca.pem -days 365 \
  -subj "/C=US/ST=CA/L=San Francisco/O=MyOrg/CN=root-ca"

# Generate node certificate
openssl genrsa -out node-key.pem 2048
openssl req -new -key node-key.pem -out node.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=MyOrg/CN=localhost"

# Create extensions file for SAN
cat > node.ext << 'EXTEOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EXTEOF

openssl x509 -req -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out node.pem -days 365 -extensions v3_req -extfile node.ext

# Generate admin certificate
openssl genrsa -out admin-key.pem 2048
openssl req -new -key admin-key.pem -out admin.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=MyOrg/CN=admin"
openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out admin.pem -days 365

# Set permissions
chmod 600 *.pem
rm *.csr node.ext

EOF
```

## Step 4: Configure OpenSearch

### Create OpenSearch Configuration
```bash
sudo -u opensearch cat > /opt/opensearch/current/config/opensearch.yml << 'EOF'
cluster.name: my-opensearch-cluster
node.name: node-1
path.data: /var/lib/opensearch
path.logs: /var/log/opensearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

# Security Configuration
plugins.security.ssl.transport.pemcert_filepath: ssl/node.pem
plugins.security.ssl.transport.pemkey_filepath: ssl/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: ssl/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: ssl/node.pem
plugins.security.ssl.http.pemkey_filepath: ssl/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: ssl/root-ca.pem
plugins.security.allow_unsafe_democertificates: true
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - CN=admin,O=MyOrg,L=San Francisco,ST=CA,C=US
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices:
  [
    ".opendistro-alerting-config",
    ".opendistro-alerting-alert*",
    ".opendistro-anomaly-results*",
    ".opendistro-anomaly-detector*",
    ".opendistro-anomaly-checkpoints",
    ".opendistro-anomaly-detection-state",
    ".opendistro-reports-*",
    ".opendistro-notifications-*",
    ".opendistro-notebooks",
    ".opendistro-asynchronous-search-response*"
  ]
EOF
```

### Configure JVM Options
```bash
sudo -u opensearch cat > /opt/opensearch/current/config/jvm.options << 'EOF'
-Xms2g
-Xmx2g
-XX:+UseG1GC
-XX:G1HeapRegionSize=32m
-XX:+UseG1GC
-XX:MaxGCPauseMillis=50
-Djava.io.tmpdir=${OPENSEARCH_TMPDIR}
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=data
-XX:ErrorFile=logs/hs_err_pid%p.log
-Xlog:gc*,gc+age=trace,safepoint:gc.log:utctime,pid,tags
-Djava.locale.providers=SPI,COMPAT
--add-modules=ALL-SYSTEM
--add-opens=java.base/java.io=ALL-UNNAMED
--add-opens=java.base/java.lang=ALL-UNNAMED
--add-opens=java.base/java.lang.invoke=ALL-UNNAMED
--add-opens=java.base/java.lang.reflect=ALL-UNNAMED
--add-opens=java.base/java.net=ALL-UNNAMED
--add-opens=java.base/java.nio=ALL-UNNAMED
--add-opens=java.base/java.security=ALL-UNNAMED
--add-opens=java.base/java.security.cert=ALL-UNNAMED
--add-opens=java.base/java.text=ALL-UNNAMED
--add-opens=java.base/java.time=ALL-UNNAMED
--add-opens=java.base/java.util=ALL-UNNAMED
--add-opens=java.base/java.util.concurrent=ALL-UNNAMED
--add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED
--add-opens=java.base/java.util.concurrent.locks=ALL-UNNAMED
--add-opens=java.base/javax.crypto=ALL-UNNAMED
--add-opens=java.base/sun.nio.ch=ALL-UNNAMED
--add-opens=java.base/sun.nio.cs=ALL-UNNAMED
--add-opens=java.base/sun.security.ssl=ALL-UNNAMED
--add-opens=java.base/sun.security.util=ALL-UNNAMED
--add-opens=java.management/sun.management=ALL-UNNAMED
EOF
```

## Step 5: Create OpenSearch Systemd Service

```bash
sudo cat > /etc/systemd/system/opensearch.service << 'EOF'
[Unit]
Description=OpenSearch
Documentation=https://opensearch.org/
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
RuntimeDirectory=opensearch
PrivateTmp=true
Environment=OPENSEARCH_HOME=/opt/opensearch/current
Environment=OPENSEARCH_PATH_CONF=/opt/opensearch/current/config
Environment=PID_DIR=/var/run/opensearch
EnvironmentFile=-/etc/default/opensearch
WorkingDirectory=/opt/opensearch/current
User=opensearch
Group=opensearch
ExecStart=/opt/opensearch/current/bin/opensearch
StandardOutput=journal
StandardError=inherit
LimitNOFILE=65535
LimitNPROC=4096
LimitAS=infinity
LimitFSIZE=infinity
TimeoutStopSec=0
KillSignal=SIGTERM
KillMode=process
SendSIGKILL=no
SuccessExitStatus=143
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
EOF
```

## Step 6: Start and Enable OpenSearch

```bash
sudo systemctl daemon-reload
sudo systemctl enable opensearch
sudo systemctl start opensearch

# Wait for OpenSearch to start
sleep 30
```

### Verify OpenSearch Installation
```bash
# Check service status
sudo systemctl status opensearch

# Test HTTPS endpoint
curl -k -u admin:admin https://localhost:9200
```

## Step 7: Download and Install OpenSearch Dashboard

### Download OpenSearch Dashboard Tarball
```bash
cd /tmp
wget https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/2.11.1/opensearch-dashboards-2.11.1-linux-x64.tar.gz
tar -xzf opensearch-dashboards-2.11.1-linux-x64.tar.gz
sudo mv opensearch-dashboards-2.11.1 /opt/opensearch-dashboards/
sudo ln -sf /opt/opensearch-dashboards/opensearch-dashboards-2.11.1 /opt/opensearch-dashboards/current
```

### Set Ownership
```bash
sudo chown -R opensearch:opensearch /opt/opensearch-dashboards/
sudo chown -R opensearch:opensearch /var/log/opensearch-dashboards/
```

## Step 8: Configure OpenSearch Dashboard with SSL

### Generate Dashboard Certificates
```bash
sudo -u opensearch bash << 'EOF'
cd /opt/opensearch/current/config/ssl

# Generate dashboard certificate
openssl genrsa -out dashboard-key.pem 2048
openssl req -new -key dashboard-key.pem -out dashboard.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=MyOrg/CN=localhost"

# Create extensions file for dashboard
cat > dashboard.ext << 'EXTEOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EXTEOF

openssl x509 -req -in dashboard.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out dashboard.pem -days 365 -extensions v3_req -extfile dashboard.ext

chmod 600 dashboard*.pem
rm dashboard.csr dashboard.ext
EOF

# Copy certificates to dashboard config
sudo mkdir -p /opt/opensearch-dashboards/current/config/ssl
sudo cp /opt/opensearch/current/config/ssl/*.pem /opt/opensearch-dashboards/current/config/ssl/
sudo chown -R opensearch:opensearch /opt/opensearch-dashboards/current/config/ssl/
```

### Configure OpenSearch Dashboard
```bash
sudo -u opensearch cat > /opt/opensearch-dashboards/current/config/opensearch_dashboards.yml << 'EOF'
server.port: 5601
server.host: "0.0.0.0"
server.ssl.enabled: true
server.ssl.certificate: /opt/opensearch-dashboards/current/config/ssl/dashboard.pem
server.ssl.key: /opt/opensearch-dashboards/current/config/ssl/dashboard-key.pem
opensearch.hosts: ["https://localhost:9200"]
opensearch.ssl.certificateAuthorities: ["/opt/opensearch-dashboards/current/config/ssl/root-ca.pem"]
opensearch.ssl.verificationMode: none
opensearch.username: "admin"
opensearch.password: "admin"
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.cookie.secure: true
logging.dest: /var/log/opensearch-dashboards/opensearch_dashboards.log
pid.file: /var/run/opensearch-dashboards.pid
EOF
```

## Step 9: Create OpenSearch Dashboard Systemd Service

```bash
sudo cat > /etc/systemd/system/opensearch-dashboards.service << 'EOF'
[Unit]
Description=OpenSearch Dashboards
Documentation=https://opensearch.org/
Wants=network-online.target
After=network-online.target opensearch.service

[Service]
Type=simple
User=opensearch
Group=opensearch
RuntimeDirectory=opensearch-dashboards
PrivateTmp=true
Environment=NODE_ENV=production
Environment=NODE_OPTIONS="--max-old-space-size=4096"
ExecStart=/opt/opensearch-dashboards/current/bin/opensearch-dashboards
WorkingDirectory=/opt/opensearch-dashboards/current
StandardOutput=journal
StandardError=inherit
KillSignal=SIGTERM
KillMode=process
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
```

## Step 10: Start and Enable OpenSearch Dashboard

```bash
sudo systemctl daemon-reload
sudo systemctl enable opensearch-dashboards
sudo systemctl start opensearch-dashboards
```

### Verify Dashboard Installation
```bash
# Check service status
sudo systemctl status opensearch-dashboards

# Access via browser: https://localhost:5601
```

## Step 11: Download and Install Logstash

### Download Logstash Tarball
```bash
cd /tmp
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.11.3-linux-x86_64.tar.gz
tar -xzf logstash-8.11.3-linux-x86_64.tar.gz
sudo mv logstash-8.11.3 /opt/logstash/
sudo ln -sf /opt/logstash/logstash-8.11.3 /opt/logstash/current
```

### Set Ownership
```bash
sudo chown -R logstash:logstash /opt/logstash/
sudo chown -R logstash:logstash /var/log/logstash/
sudo mkdir -p /etc/logstash/conf.d
sudo chown -R logstash:logstash /etc/logstash/
```

## Step 12: Configure Logstash for OpenSearch with SSL

### Copy SSL Certificates for Logstash
```bash
sudo mkdir -p /opt/logstash/current/config/ssl
sudo cp /opt/opensearch/current/config/ssl/root-ca.pem /opt/logstash/current/config/ssl/
sudo chown -R logstash:logstash /opt/logstash/current/config/ssl/
```

### Create Logstash Configuration
```bash
sudo -u logstash cat > /etc/logstash/conf.d/opensearch.conf << 'EOF'
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/opt/logstash/current/config/ssl/node.pem"
    ssl_key => "/opt/logstash/current/config/ssl/node-key.pem"
  }
  
  syslog {
    port => 5000
  }
  
  stdin { }
  
  http {
    port => 8080
    codec => json
  }
}

filter {
  if [fields][log_type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{IPORHOST:syslog_server} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
  
  # Add timestamp if not present
  if ![timestamp] {
    mutate {
      add_field => { "timestamp" => "%{@timestamp}" }
    }
  }
}

output {
  opensearch {
    hosts => ["https://localhost:9200"]
    user => "admin"
    password => "admin"
    index => "logstash-%{+YYYY.MM.dd}"
    ssl => true
    ssl_certificate_verification => false
    cacert => "/opt/logstash/current/config/ssl/root-ca.pem"
    template_name => "logstash"
    template_pattern => "logstash-*"
    template_overwrite => true
  }
  
  stdout {
    codec => rubydebug
  }
}
EOF
```

### Configure Logstash Settings
```bash
sudo -u logstash cat > /opt/logstash/current/config/logstash.yml << 'EOF'
node.name: logstash-node-1
path.data: /opt/logstash/current/data
pipeline.workers: 2
pipeline.batch.size: 125
pipeline.batch.delay: 50
path.config: /etc/logstash/conf.d/*.conf
path.logs: /var/log/logstash
xpack.monitoring.enabled: false
api.http.host: "127.0.0.1"
api.http.port: 9600-9700
log.level: info
path.settings: /opt/logstash/current/config
EOF
```

### Configure Logstash JVM Options
```bash
sudo -u logstash cat > /opt/logstash/current/config/jvm.options << 'EOF'
-Xms1g
-Xmx1g
-XX:+UseG1GC
-XX:MaxGCPauseMillis=50
-XX:G1HeapRegionSize=16m
-XX:+UseStringDeduplication
-Djava.awt.headless=true
-Dfile.encoding=UTF-8
-Djava.security.egd=file:/dev/urandom
-Dlog4j2.isThreadContextMapInheritable=true
--add-opens=java.base/java.security=ALL-UNNAMED
--add-opens=java.base/java.io=ALL-UNNAMED
--add-opens=java.base/java.nio.channels=ALL-UNNAMED
--add-opens=java.base/sun.nio.ch=ALL-UNNAMED
--add-opens=java.management/sun.management=ALL-UNNAMED
--add-opens=java.base/java.lang=ALL-UNNAMED
--add-opens=java.base/java.lang.reflect=ALL-UNNAMED
--add-opens=java.base/java.util=ALL-UNNAMED
--add-opens=java.base/java.util.concurrent=ALL-UNNAMED
--add-opens=java.security.jgss/sun.security.krb5=ALL-UNNAMED
EOF
```

## Step 13: Create Logstash Systemd Service

```bash
sudo cat > /etc/systemd/system/logstash.service << 'EOF'
[Unit]
Description=logstash
Documentation=https://www.elastic.co/logstash
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=logstash
Group=logstash
RuntimeDirectory=logstash
WorkingDirectory=/opt/logstash/current
Environment=LS_HOME=/opt/logstash/current
Environment=LS_SETTINGS_DIR=/opt/logstash/current/config
Environment=LS_JAVA_OPTS="-Dlog4j2.formatMsgNoLookups=true"
ExecStart=/opt/logstash/current/bin/logstash "--path.settings" "/opt/logstash/current/config"
StandardOutput=journal
StandardError=inherit
LimitNOFILE=16384
TimeoutStopSec=30
KillSignal=SIGTERM
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
```

## Step 14: Start and Enable Logstash

```bash
sudo systemctl daemon-reload
sudo systemctl enable logstash
sudo systemctl start logstash
```

### Verify Logstash Installation
```bash
# Check service status
sudo systemctl status logstash

# Check logs
sudo journalctl -u logstash -f
```

## Step 15: Test the Complete Stack

### Test Log Ingestion
```bash
# Test via HTTP input
curl -X POST "http://localhost:8080" -H 'Content-Type: application/json' -d'
{
  "message": "Test log message from HTTP",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
  "level": "INFO"
}
'

# Test via stdin (interactive)
echo '{"message": "Test stdin message", "level": "DEBUG"}' | sudo -u logstash /opt/logstash/current/bin/logstash -f /etc/logstash/conf.d/opensearch.conf --path.settings /opt/logstash/current/config
```

### Verify Data in OpenSearch
```bash
# Check indices
curl -k -u admin:admin -X GET "https://localhost:9200/_cat/indices?v"

# Search for data
curl -k -u admin:admin -X GET "https://localhost:9200/logstash-*/_search?pretty&size=5"
```

## Step 16: Environment Variables and Startup Scripts

### Create Environment Files
```bash
# OpenSearch environment
sudo cat > /etc/default/opensearch << 'EOF'
OPENSEARCH_JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
OPENSEARCH_HOME=/opt/opensearch/current
OPENSEARCH_PATH_CONF=/opt/opensearch/current/config
MAX_OPEN_FILES=65535
MAX_LOCKED_MEMORY=unlimited
EOF

# Logstash environment
sudo cat > /etc/default/logstash << 'EOF'
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
LS_HOME=/opt/logstash/current
LS_SETTINGS_DIR=/opt/logstash/current/config
LS_JAVA_OPTS="-Dlog4j2.formatMsgNoLookups=true"
EOF
```

## Step 17: Security Hardening (Production)

### Change Default Passwords
```bash
# Use the security admin tool to update passwords
sudo -u opensearch /opt/opensearch/current/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /opt/opensearch/current/plugins/opensearch-security/securityconfig/ \
  -icl -key /opt/opensearch/current/config/ssl/admin-key.pem \
  -cert /opt/opensearch/current/config/ssl/admin.pem \
  -cacert /opt/opensearch/current/config/ssl/root-ca.pem \
  -nhnv
```

### Configure Firewall
```bash
# Ubuntu/Debian
sudo ufw allow 9200/tcp  # OpenSearch
sudo ufw allow 5601/tcp  # Dashboard
sudo ufw allow 5044/tcp  # Logstash Beats input
sudo ufw allow 8080/tcp  # Logstash HTTP input
sudo ufw enable

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=9200/tcp
sudo firewall-cmd --permanent --add-port=5601/tcp
sudo firewall-cmd --permanent --add-port=5044/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### Set File Limits
```bash
# Add to /etc/security/limits.conf
sudo cat >> /etc/security/limits.conf << 'EOF'
opensearch soft nofile 65535
opensearch hard nofile 65535
opensearch soft memlock unlimited
opensearch hard memlock unlimited
logstash soft nofile 16384
logstash hard nofile 16384
EOF

# Add to /etc/sysctl.conf
sudo cat >> /etc/sysctl.conf << 'EOF'
vm.max_map_count=262144
EOF
sudo sysctl -p
```

## Step 18: Monitoring and Maintenance

### Check All Services
```bash
sudo systemctl status opensearch opensearch-dashboards logstash
```

### View All Logs
```bash
# OpenSearch logs
sudo journalctl -u opensearch -f

# Dashboard logs
sudo journalctl -u opensearch-dashboards -f

# Logstash logs
sudo journalctl -u logstash -f

# Or check log files directly
sudo tail -f /var/log/opensearch/my-opensearch-cluster.log
sudo tail -f /var/log/opensearch-dashboards/opensearch_dashboards.log
sudo tail -f /var/log/logstash/logstash-plain.log
```

### Monitor Resources
```bash
# Check disk usage
df -h

# Check memory usage
free -h

# Check Java processes
ps aux | grep java

# Check OpenSearch cluster health
curl -k -u admin:admin -X GET "https://localhost:9200/_cluster/health?pretty"

# Check OpenSearch node info
curl -k -u admin:admin -X GET "https://localhost:9200/_nodes?pretty"
```

### Restart All Services
```bash
sudo systemctl restart opensearch
sleep 30
sudo systemctl restart opensearch-dashboards
sudo systemctl restart logstash
```

## Step 19: Backup and Restore

### Create Backup Script
```bash
sudo cat > /opt/backup-opensearch.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/backups/opensearch/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup configurations
cp -r /opt/opensearch/current/config $BACKUP_DIR/opensearch-config
cp -r /opt/opensearch-dashboards/current/config $BACKUP_DIR/dashboard-config
cp -r /etc/logstash $BACKUP_DIR/logstash-config

# Backup SSL certificates
cp -r /opt/opensearch/current/config/ssl $BACKUP_DIR/ssl-certificates

echo "Backup completed: $BACKUP_DIR"
EOF

sudo chmod +x /opt/backup-opensearch.sh
```

## Step 20: Troubleshooting

### Common Issues and Solutions

1. **Permission Issues**:
```bash
# Fix ownership
sudo chown -R opensearch:opensearch /opt/opensearch/
sudo chown -R opensearch:opensearch /opt/opensearch-dashboards/
sudo chown -R logstash:logstash /opt/logstash/
```

2. **Memory Issues**:
```bash
# Check current memory usage
free -h
# Adjust JVM settings in respective jvm.options files
```

3. **SSL Certificate Issues**:
```bash
# Verify certificate validity
openssl x509 -in /opt/opensearch/current/config/ssl/node.pem -text -noout

# Check certificate expiration
openssl x509 -in /opt/opensearch/current/config/ssl/node.pem -noout -dates
```

4. **Port Conflicts**:
```bash
# Check what's using the ports
sudo netstat -tlnp | grep -E ':(9200|5601|5044|8080)'
sudo lsof -i :9200
```

5. **Service Start Issues**:
```bash
# Check detailed logs
sudo journalctl -u opensearch --no-pager -l
sudo journalctl -u opensearch-dashboards --no-pager -l
sudo journalctl -u logstash --no-pager -l
```

### Useful Debug Commands
```bash
# Test OpenSearch directly
/opt/opensearch/current/bin/opensearch -d

# Test Logstash configuration
sudo -u logstash /opt/logstash/current/bin/logstash -f /etc/logstash/conf.d/opensearch.conf --config.test_and_exit

# Check OpenSearch plugins
/opt/opensearch/current/bin/opensearch-plugin list

# Check network connectivity
curl -k -u admin:admin https://localhost:9200/_cat/health?v
curl -k https://localhost:5601/api/status
```

## Conclusion

You now have a complete OpenSearch stack installed from tarball binaries with SSL security:

- **OpenSearch**: Running on port 9200 with HTTPS at `/opt/opensearch/current/`
- **OpenSearch Dashboard**: Running on port 5601 with HTTPS at `/opt/opensearch-dashboards/current/`
- **Logstash**: Running with multiple inputs at `/opt/logstash/current/`

**Access Points:**
- OpenSearch API: `https://localhost:9200` (admin/admin)
- OpenSearch Dashboard: `https://localhost:5601` (admin/admin)
- Logstash HTTP input: `http://localhost:8080`
- Logstash Beats input: `localhost:5044`

**Key Benefits of Tarball Installation:**
- Full control over installation directory
- Easy to upgrade by changing symlinks
- Custom configurations without package manager conflicts
- Portable across different Linux distributions

Remember to change default passwords and use proper SSL certificates in production!