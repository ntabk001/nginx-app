# Hướng dẫn toàn diện về Filebeat

## 1. Giới thiệu về Filebeat

### Filebeat là gì?
Filebeat là một lightweight shipper thuộc Elastic Stack (ELK Stack), được thiết kế để thu thập, chuyển tiếp và tập trung log data. Đây là một agent nhẹ được cài đặt trên server để monitor log files hoặc locations mà bạn chỉ định, thu thập log events và forward chúng đến Elasticsearch hoặc Logstash để index.

### Đặc điểm chính
- **Lightweight**: Tiêu thụ ít tài nguyên hệ thống
- **Reliable**: Đảm bảo at-least-once delivery
- **Secure**: Hỗ trợ TLS và authentication
- **Flexible**: Có thể gửi đến nhiều outputs khác nhau
- **Easy to deploy**: Dễ cài đặt và cấu hình

### Kiến trúc hoạt động
```
Log Files → Filebeat → Processing → Output (Elasticsearch/Logstash/Kafka...)
```

## 2. Cài đặt Filebeat

### Trên Ubuntu/Debian
```bash
# Import Elastic GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

# Add repository
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update và install
sudo apt update
sudo apt install filebeat

# Enable service
sudo systemctl enable filebeat
```

### Trên CentOS/RHEL
```bash
# Import GPG key
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

# Tạo repo file
cat > /etc/yum.repos.d/elastic.repo << EOF
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Install
sudo yum install filebeat

# Enable service
sudo systemctl enable filebeat
```

### Trên Docker
```bash
docker run -d \
  --name=filebeat \
  --user=root \
  --volume="$(pwd)/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro" \
  --volume="/var/lib/docker/containers:/var/lib/docker/containers:ro" \
  --volume="/var/run/docker.sock:/var/run/docker.sock:ro" \
  docker.elastic.co/beats/filebeat:8.11.0
```

## 3. Cấu hình cơ bản

### Cấu trúc file cấu hình
File cấu hình chính: `/etc/filebeat/filebeat.yml`

```yaml
# ======================== Filebeat inputs =============================
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/myapp/*.log

# ======================= Elasticsearch template setting =======================
setup.template.settings:
  index.number_of_shards: 1
  index.codec: best_compression

# =========================== Filebeat modules ==============================
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

# ==================== Elasticsearch template setting ====================
setup.template.name: "filebeat"
setup.template.pattern: "filebeat-*"

# ================================ Outputs ===================================
output.elasticsearch:
  hosts: ["localhost:9200"]

# ================================= Dashboards =================================
setup.dashboards.enabled: true

# ================================== Logging ===================================
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
```

### Cấu hình Input cơ bản

#### Log Input
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/apache2/access.log
    - /var/log/apache2/error.log
  fields:
    logtype: apache
    environment: production
  fields_under_root: true
  multiline.pattern: '^\d{4}-\d{2}-\d{2}'
  multiline.negate: true
  multiline.match: after
```

#### Docker Input
```yaml
filebeat.inputs:
- type: docker
  containers.ids:
    - "*"
  processors:
    - add_docker_metadata:
        host: "unix:///var/run/docker.sock"
```

#### Syslog Input
```yaml
filebeat.inputs:
- type: syslog
  protocol.udp:
    host: "localhost:514"
```

## 4. Cấu hình Output

### Elasticsearch Output
```yaml
output.elasticsearch:
  hosts: ["elasticsearch1:9200", "elasticsearch2:9200"]
  username: "elastic"
  password: "changeme"
  index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"
  template.name: "filebeat"
  template.pattern: "filebeat-*"
  ssl:
    enabled: true
    certificate_authorities: ["/etc/ssl/certs/ca.crt"]
    certificate: "/etc/ssl/certs/client.crt"
    key: "/etc/ssl/private/client.key"
```

### Logstash Output
```yaml
output.logstash:
  hosts: ["logstash1:5044", "logstash2:5044"]
  loadbalance: true
  ssl:
    enabled: true
    certificate_authorities: ["/etc/ssl/certs/ca.crt"]
```

### Kafka Output
```yaml
output.kafka:
  hosts: ["kafka1:9092", "kafka2:9092"]
  topic: 'filebeat-logs'
  partition.round_robin:
    reachable_only: false
  required_acks: 1
  compression: gzip
  max_message_bytes: 1000000
```

### Redis Output
```yaml
output.redis:
  hosts: ["redis:6379"]
  key: "filebeat-logs"
  db: 0
  timeout: 5s
```

## 5. Processors (Xử lý dữ liệu)

### Add fields
```yaml
processors:
- add_fields:
    target: ""
    fields:
      service: myapp
      environment: production
      datacenter: us-east-1
```

### Drop fields
```yaml
processors:
- drop_fields:
    fields: ["agent.ephemeral_id", "agent.hostname", "agent.id"]
```

### Add tags
```yaml
processors:
- add_tags:
    tags: [web, production]
```

### Decode JSON
```yaml
processors:
- decode_json_fields:
    fields: ["message"]
    target: ""
    overwrite_keys: true
```

### Timestamp parsing
```yaml
processors:
- timestamp:
    field: json.timestamp
    layouts:
      - '2006-01-02T15:04:05.000Z'
      - '2006-01-02T15:04:05Z'
    test:
      - '2019-06-22T16:33:51Z'
```

### Dissect processor
```yaml
processors:
- dissect:
    tokenizer: "%{timestamp} %{+timestamp} %{+timestamp} %{level} %{message}"
    field: "message"
    target_prefix: ""
```

## 6. Modules (Sử dụng sẵn)

### Kích hoạt modules
```bash
# List available modules
sudo filebeat modules list

# Enable module
sudo filebeat modules enable apache nginx mysql

# Disable module
sudo filebeat modules disable apache
```

### Cấu hình Apache module
```yaml
# /etc/filebeat/modules.d/apache.yml
- module: apache
  access:
    enabled: true
    var.paths: ["/var/log/apache2/access.log*"]
  error:
    enabled: true
    var.paths: ["/var/log/apache2/error.log*"]
```

### Cấu hình Nginx module
```yaml
# /etc/filebeat/modules.d/nginx.yml
- module: nginx
  access:
    enabled: true
    var.paths: ["/var/log/nginx/access.log*"]
  error:
    enabled: true
    var.paths: ["/var/log/nginx/error.log*"]
```

### Cấu hình System module
```yaml
# /etc/filebeat/modules.d/system.yml
- module: system
  syslog:
    enabled: true
    var.paths: ["/var/log/syslog*"]
  auth:
    enabled: true
    var.paths: ["/var/log/auth.log*"]
```

## 7. Multiline Processing

### Java Stack Traces
```yaml
filebeat.inputs:
- type: log
  paths: ["/var/log/myapp/*.log"]
  multiline.pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
  multiline.negate: true
  multiline.match: after
  multiline.max_lines: 500
```

### C-style continuation
```yaml
multiline.pattern: '\\$'
multiline.negate: false
multiline.match: before
```

### XML messages
```yaml
multiline.pattern: '<\?xml.*\?>'
multiline.negate: true
multiline.match: after
```

## 8. Filtering và Conditions

### Include/Exclude lines
```yaml
filebeat.inputs:
- type: log
  paths: ["/var/log/myapp.log"]
  include_lines: ['^ERR', '^WARN']
  exclude_lines: ['^DEBUG']
```

### Exclude files
```yaml
filebeat.inputs:
- type: log
  paths: ["/var/log/*.log"]
  exclude_files: ['\.gz$', 'tmp.*']
```

### Conditional processing
```yaml
processors:
- drop_event:
    when:
      equals:
        log.level: "debug"
```

## 9. Performance Tuning

### Harvester settings
```yaml
filebeat.inputs:
- type: log
  paths: ["/var/log/*.log"]
  harvester_buffer_size: 16384
  max_bytes: 10485760
  close_inactive: 5m
  close_removed: true
  close_renamed: false
  clean_inactive: 72h
```

### Queue settings
```yaml
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 1s
```

### Output workers
```yaml
output.elasticsearch:
  hosts: ["localhost:9200"]
  worker: 2
  bulk_max_size: 2048
  flush_interval: 1s
```

## 10. Security Configuration

### TLS Configuration
```yaml
output.elasticsearch:
  hosts: ["https://localhost:9200"]
  ssl:
    enabled: true
    certificate_authorities: ["/etc/ssl/certs/ca.pem"]
    certificate: "/etc/ssl/certs/client.pem"
    key: "/etc/ssl/private/client-key.pem"
    verification_mode: certificate
```

### API Key Authentication
```yaml
output.elasticsearch:
  hosts: ["https://localhost:9200"]
  api_key: "your-api-key-here"
```

### Basic Authentication
```yaml
output.elasticsearch:
  hosts: ["https://localhost:9200"]
  username: "filebeat_internal"
  password: "your-password-here"
```

## 11. Monitoring và Debugging

### Enable monitoring
```yaml
monitoring.enabled: true
monitoring.elasticsearch:
  hosts: ["http://localhost:9200"]
```

### Logging configuration
```yaml
logging.level: debug
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0600
```

### Test configuration
```bash
# Test config file
sudo filebeat test config

# Test output
sudo filebeat test output
```

## 12. Commands hữu ích

### Basic commands
```bash
# Start Filebeat
sudo systemctl start filebeat

# Stop Filebeat
sudo systemctl stop filebeat

# Restart Filebeat
sudo systemctl restart filebeat

# Check status
sudo systemctl status filebeat

# View logs
sudo journalctl -u filebeat -f
```

### Setup commands
```bash
# Setup index template
sudo filebeat setup --index-management

# Setup dashboards
sudo filebeat setup --dashboards

# Setup machine learning
sudo filebeat setup --machine-learning
```

### Export commands
```bash
# Export config
sudo filebeat export config

# Export index template
sudo filebeat export template > filebeat.template.json

# Export ILM policy
sudo filebeat export ilm-policy
```

## 13. Troubleshooting

### Common issues và solutions

#### Filebeat không start được
```bash
# Check config syntax
sudo filebeat test config -c /etc/filebeat/filebeat.yml

# Check permissions
sudo chown root:root /etc/filebeat/filebeat.yml
sudo chmod 600 /etc/filebeat/filebeat.yml
```

#### Log không được gửi đến Elasticsearch
```bash
# Test connectivity
curl -X GET "localhost:9200/_cluster/health"

# Check Filebeat registry
sudo ls -la /var/lib/filebeat/registry/
```

#### High memory usage
```yaml
# Reduce queue size
queue.mem:
  events: 1024
  flush.min_events: 256

# Reduce bulk size
output.elasticsearch:
  bulk_max_size: 512
```

## 14. Best Practices

### Performance
- Sử dụng SSD để lưu registry data
- Tune harvester buffer size phù hợp
- Sử dụng multiple workers cho output
- Enable gzip compression cho network transfer

### Security
- Luôn sử dụng TLS cho production
- Sử dụng dedicated user cho Filebeat
- Restrict file permissions (600 cho config files)
- Regular update Filebeat version

### Monitoring
- Enable monitoring để track performance
- Set up alerts cho Filebeat down
- Monitor registry file size
- Track harvester lag

### Configuration Management
- Version control cho config files
- Use environment variables cho sensitive data
- Test configuration trước khi deploy
- Document tất cả customizations

## 15. Ví dụ thực tế

### Multi-environment setup
```yaml
filebeat.inputs:
- type: log
  paths: ["/var/log/app/*.log"]
  fields:
    env: "${ENV:dev}"
    service: "webapp"
  processors:
  - add_host_metadata: ~
  - add_docker_metadata: ~

output.elasticsearch:
  hosts: ["${ES_HOST:localhost}:${ES_PORT:9200}"]
  index: "logs-%{[fields.env]}-%{+yyyy.MM.dd}"
```

### Container logging
```yaml
filebeat.autodiscover:
  providers:
    - type: docker
      hints.enabled: true
      hints.default_config:
        type: container
        paths:
          - /var/lib/docker/containers/${data.docker.container.id}/*.log
```

Đây là tài liệu tổng hợp toàn diện về Filebeat. Bạn có thể tham khảo và áp dụng theo nhu cầu cụ thể của hệ thống.