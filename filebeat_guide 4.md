# Hướng dẫn toàn diện về Filebeat và Logstash

## 1. Giới thiệu về ELK Stack

### ELK Stack là gì?
ELK Stack bao gồm Elasticsearch, Logstash và Kibana - một bộ công cụ mạnh mẽ để thu thập, xử lý, lưu trữ và visualize log data. Filebeat đóng vai trò là lightweight shipper thu thập logs.

### Filebeat là gì?
Filebeat là một lightweight shipper thuộc Elastic Stack, được thiết kế để thu thập, chuyển tiếp và tập trung log data. Đây là một agent nhẹ được cài đặt trên server để monitor log files hoặc locations mà bạn chỉ định, thu thập log events và forward chúng đến Elasticsearch hoặc Logstash để index.

### Logstash là gì?
Logstash là một server-side data processing pipeline mạnh mẽ, có khả năng ingests data từ nhiều nguồn đồng thời, transform nó và gửi đến Elasticsearch hoặc các "stash" khác. Logstash hoạt động theo mô hình Input → Filter → Output.

### Kiến trúc hoạt động tổng thể
```
Log Files → Filebeat → Logstash → Elasticsearch → Kibana
          (Collect)   (Process)   (Store)      (Visualize)
```

### Đặc điểm chính của Filebeat
- **Lightweight**: Tiêu thụ ít tài nguyên hệ thống
- **Reliable**: Đảm bảo at-least-once delivery
- **Secure**: Hỗ trợ TLS và authentication
- **Flexible**: Có thể gửi đến nhiều outputs khác nhau
- **Easy to deploy**: Dễ cài đặt và cấu hình

### Đặc điểm chính của Logstash
- **Powerful processing**: Hàng trăm plugins để xử lý data
- **Flexible pipeline**: Input → Filter → Output với nhiều plugins
- **Scalable**: Có thể scale horizontal
- **Real-time**: Xử lý data theo thời gian thực

## 2. Cài đặt Filebeat và Logstash trên RHEL/CentOS

### Cài đặt Repository
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
```

### Cài đặt Filebeat
```bash
# Install Filebeat
sudo yum install filebeat

# Enable service
sudo systemctl enable filebeat

# Start service
sudo systemctl start filebeat
```

### Cài đặt Logstash
```bash
# Install Java (prerequisite for Logstash)
sudo yum install java-11-openjdk java-11-openjdk-devel

# Install Logstash
sudo yum install logstash

# Enable service
sudo systemctl enable logstash

# Start service (sau khi cấu hình)
# sudo systemctl start logstash
```

### Cài đặt bằng Docker
```bash
# Filebeat
docker run -d \
  --name=filebeat \
  --user=root \
  --volume="$(pwd)/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro" \
  --volume="/var/lib/docker/containers:/var/lib/docker/containers:ro" \
  --volume="/var/run/docker.sock:/var/run/docker.sock:ro" \
  docker.elastic.co/beats/filebeat:8.11.0

# Logstash
docker run -d \
  --name=logstash \
  --volume="$(pwd)/logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro" \
  --volume="$(pwd)/logstash.yml:/usr/share/logstash/config/logstash.yml:ro" \
  -p 5044:5044 \
  docker.elastic.co/logstash/logstash:8.11.0
```

## 3. Cấu hình cơ bản Filebeat

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

## 4. Cấu hình Output Filebeat

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

## 9. Performance Tuning Filebeat

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

## 14. Logstash Configuration và Processing

### Cấu trúc cơ bản Logstash
Logstash hoạt động theo mô hình pipeline với 3 stages chính:
- **Input**: Nhận data từ nhiều nguồn
- **Filter**: Xử lý, transform và enrich data
- **Output**: Gửi data đến destination

### File cấu hình chính
- **logstash.yml**: Cấu hình chính của Logstash (`/etc/logstash/logstash.yml`)
- **pipeline.yml**: Cấu hình pipeline (`/etc/logstash/conf.d/main.conf`)

### Cấu hình logstash.yml
```yaml
# /etc/logstash/logstash.yml
node.name: logstash-server-01
path.data: /var/lib/logstash
pipeline.workers: 2
pipeline.batch.size: 125
pipeline.batch.delay: 50
path.config: /etc/logstash/conf.d/*.conf
path.logs: /var/log/logstash
xpack.monitoring.enabled: true
xpack.monitoring.elasticsearch.hosts: ["http://localhost:9200"]
```

### Cấu hình Pipeline cơ bản
```ruby
# /etc/logstash/conf.d/main.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][logtype] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
}
```

## 15. Input Plugins Logstash

### Beats Input (Nhận từ Filebeat)
```ruby
input {
  beats {
    port => 5044
    type => "log"
    codec => "json"
  }
}
```

### File Input
```ruby
input {
  file {
    path => ["/var/log/*.log", "/var/log/**/*.log"]
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => "multiline" {
      pattern => "^%{TIMESTAMP_ISO8601}"
      negate => true
      what => "previous"
    }
  }
}
```

### Syslog Input
```ruby
input {
  syslog {
    port => 514
    type => "syslog"
  }
}
```

### TCP Input
```ruby
input {
  tcp {
    port => 5000
    type => "tcp"
    codec => json_lines
  }
}
```

### HTTP Input
```ruby
input {
  http {
    port => 8080
    codec => "json"
  }
}
```

### Kafka Input
```ruby
input {
  kafka {
    bootstrap_servers => "kafka1:9092,kafka2:9092"
    topics => ["logs"]
    group_id => "logstash"
    consumer_threads => 3
  }
}
```

## 16. Filter Plugins Logstash

### Grok Pattern Matching
```ruby
filter {
  grok {
    match => { "message" => "%{COMBINEDAPACHELOG}" }
  }
  
  # Custom pattern
  grok {
    match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}" }
  }
  
  # Multiple patterns
  grok {
    match => { 
      "message" => [
        "%{COMBINEDAPACHELOG}",
        "%{COMMONAPACHELOG}",
        "%{GREEDYDATA:unparsed}"
      ]
    }
  }
}
```

### Mutate (Modify fields)
```ruby
filter {
  mutate {
    add_field => { "environment" => "production" }
    rename => { "old_field" => "new_field" }
    remove_field => ["unwanted_field", "another_field"]
    convert => { "response_time" => "integer" }
    gsub => [ "message", "/", "_" ]
    uppercase => [ "status" ]
    lowercase => [ "method" ]
  }
}
```

### Date Filter
```ruby
filter {
  date {
    match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    target => "@timestamp"
  }
}
```

### JSON Filter
```ruby
filter {
  json {
    source => "message"
    target => "parsed_json"
  }
}
```

### GeoIP Filter
```ruby
filter {
  geoip {
    source => "client_ip"
    target => "geoip"
    fields => ["city_name", "country_name", "location"]
  }
}
```

### User Agent Filter
```ruby
filter {
  useragent {
    source => "user_agent"
    target => "ua"
  }
}
```

### Conditional Processing
```ruby
filter {
  if [fields][logtype] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
  } else if [fields][logtype] == "nginx" {
    grok {
      match => { "message" => "%{NGINXACCESS}" }
    }
  }
  
  # Nested conditions
  if [response_code] {
    if [response_code] >= 400 {
      mutate {
        add_tag => ["error"]
      }
    } else {
      mutate {
        add_tag => ["success"]
      }
    }
  }
}
```

### Ruby Filter (Custom logic)
```ruby
filter {
  ruby {
    code => '
      if event.get("response_time")
        response_time = event.get("response_time").to_f
        if response_time > 5.0
          event.set("performance", "slow")
        elsif response_time > 2.0
          event.set("performance", "medium")
        else
          event.set("performance", "fast")
        end
      end
    '
  }
}
```

## 17. Output Plugins Logstash

### Elasticsearch Output
```ruby
output {
  elasticsearch {
    hosts => ["elasticsearch1:9200", "elasticsearch2:9200"]
    index => "%{logtype}-logs-%{+YYYY.MM.dd}"
    template_name => "custom-template"
    template_pattern => "*-logs-*"
  }
}
```

## 21. Logstash Management và Commands

### Basic Commands
```bash
# Start Logstash
sudo systemctl start logstash

# Stop Logstash
sudo systemctl stop logstash

# Restart Logstash
sudo systemctl restart logstash

# Check status
sudo systemctl status logstash

# View logs
sudo journalctl -u logstash -f
sudo tail -f /var/log/logstash/logstash-plain.log
```

### Configuration Testing
```bash
# Test configuration syntax
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/

# Debug mode
sudo /usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/ --config.debug

# Reload configuration without restart
sudo systemctl reload logstash
```

### Pipeline Management
```bash
# List pipelines
curl -X GET "localhost:9600/_node/pipelines?pretty"

# Get pipeline stats
curl -X GET "localhost:9600/_node/stats/pipelines?pretty"

# Hot reload pipeline
curl -X PUT "localhost:9600/_node/pipeline/main?pretty" -H 'Content-Type: application/json' -d'
{
  "pipeline": "input { stdin {} } output { stdout {} }"
}
'
```

## 22. Monitoring và Troubleshooting Logstash

### Enable Monitoring
```yaml
# logstash.yml
xpack.monitoring.enabled: true
xpack.monitoring.elasticsearch.hosts: ["http://localhost:9200"]
xpack.monitoring.collection.interval: 10s
```

### API Monitoring
```bash
# Node info
curl -X GET "localhost:9600/_node?pretty"

# Node stats
curl -X GET "localhost:9600/_node/stats?pretty"

# Pipeline stats
curl -X GET "localhost:9600/_node/stats/pipelines?pretty"

# Hot threads
curl -X GET "localhost:9600/_node/hot_threads?pretty"
```

### Common Issues và Solutions

#### High Memory Usage
```yaml
# Giảm batch size
pipeline.batch.size: 125

# Giảm số workers
pipeline.workers: 1

# Tune JVM
-Xms1g
-Xmx1g
```

#### Slow Processing
```ruby
# Add fingerprint để tránh duplicate processing
filter {
  fingerprint {
    source => ["host", "@timestamp", "message"]
    target => "[@metadata][fingerprint]"
    method => "SHA1"
  }
}

output {
  elasticsearch {
    document_id => "%{[@metadata][fingerprint]}"
  }
}
```

#### Pipeline Blocked
```bash
# Check pipeline stats
curl -X GET "localhost:9600/_node/stats/pipelines?pretty" | jq '.pipelines.main.events'

# Check queue
ls -la /var/lib/logstash/queue/

# Clear queue if needed
sudo systemctl stop logstash
sudo rm -rf /var/lib/logstash/queue/*
sudo systemctl start logstash
```

## 23. Advanced Use Cases

### Log Aggregation từ Multiple Sources
```ruby
# Logstash config cho multiple input sources
input {
  # Từ Filebeat
  beats {
    port => 5044
    type => "filebeat"
  }
  
  # Trực tiếp từ syslog
  syslog {
    port => 514
    type => "syslog"
  }
  
  # Từ application qua HTTP
  http {
    port => 8080
    type => "http"
    codec => json
  }
  
  # Từ Kafka
  kafka {
    bootstrap_servers => "kafka1:9092,kafka2:9092"
    topics => ["application-logs", "system-logs"]
    group_id => "logstash-consumer"
    type => "kafka"
  }
}

filter {
  # Routing based on input type
  if [type] == "filebeat" {
    # Process filebeat data
    if [fields][service] == "web" {
      grok {
        match => { "message" => "%{NGINXACCESS}" }
      }
    } else if [fields][service] == "api" {
      json {
        source => "message"
      }
    }
    
  } else if [type] == "syslog" {
    # Process syslog data
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}: %{GREEDYDATA:message}" }
    }
    
  } else if [type] == "http" {
    # HTTP input already JSON
    mutate {
      add_field => { "input_method" => "http_direct" }
    }
    
  } else if [type] == "kafka" {
    # Process Kafka messages
    json {
      source => "message"
    }
  }
  
  # Common enrichment
  mutate {
    add_field => { 
      "processing_node" => "%{HOSTNAME}"
      "ingestion_time" => "%{@timestamp}"
    }
  }
}
```

### Data Pipeline với Conditional Routing
```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  # Parse message format
  if [message] =~ /^\{.*\}$/ {
    json {
      source => "message"
    }
    mutate { add_tag => ["json_format"] }
  } else {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:content}" }
    }
    mutate { add_tag => ["text_format"] }
  }
  
  # Data validation và cleanup
  if [level] {
    mutate {
      uppercase => ["level"]
    }
    
    if [level] not in ["DEBUG", "INFO", "WARN", "ERROR", "FATAL"] {
      mutate {
        replace => { "level" => "UNKNOWN" }
        add_tag => ["invalid_log_level"]
      }
    }
  }
  
  # Sensitive data masking
  mutate {
    gsub => [
      "message", "password=\S+", "password=***",
      "message", "api_key=\S+", "api_key=***",
      "message", "\b\d{4}-\d{4}-\d{4}-\d{4}\b", "****-****-****-****"
    ]
  }
  
  # Performance metrics calculation
  if [response_time] {
    mutate { convert => { "response_time" => "float" } }
    
    ruby {
      code => '
        rt = event.get("response_time")
        if rt < 100
          event.set("performance_category", "excellent")
        elsif rt < 500
          event.set("performance_category", "good")
        elsif rt < 2000
          event.set("performance_category", "acceptable")
        else
          event.set("performance_category", "poor")
        end
      '
    }
  }
}

output {
  # Route theo severity
  if [level] in ["ERROR", "FATAL"] {
    elasticsearch {
      hosts => ["es-errors:9200"]
      index => "error-logs-%{+YYYY.MM.dd}"
    }
    
    # Alert system
    http {
      url => "http://alertmanager:9093/api/v1/alerts"
      http_method => "post"
      format => "json"
      mapping => {
        "receiver" => "web.hook"
        "status" => "firing"
        "alerts" => [{
          "status" => "firing"
          "labels" => {
            "alertname" => "ApplicationError"
            "severity" => "critical"
            "instance" => "%{host}"
            "service" => "%{[fields][service]}"
          }
          "annotations" => {
            "summary" => "Application error detected"
            "description" => "%{message}"
          }
        }]
      }
    }
    
  } else if [level] == "WARN" {
    elasticsearch {
      hosts => ["es-warnings:9200"]
      index => "warning-logs-%{+YYYY.MM.dd}"
    }
    
  } else {
    elasticsearch {
      hosts => ["es-general:9200"]
      index => "general-logs-%{+YYYY.MM.dd}"
    }
  }
  
  # Performance data routing
  if [performance_category] == "poor" {
    kafka {
      bootstrap_servers => "kafka1:9092"
      topic_id => "performance-alerts"
      codec => json
    }
  }
  
  # Backup tất cả data
  file {
    path => "/backup/logs/%{+YYYY}/%{+MM}/%{+dd}/all-logs.json"
    codec => json_lines
  }
}
```

### Metrics và Analytics Processing
```ruby
# Advanced metrics processing
input {
  beats {
    port => 5044
  }
}

filter {
  # Extract metrics từ log messages
  if [message] =~ /METRIC/ {
    grok {
      match => { 
        "message" => "METRIC %{WORD:metric_name}=%{NUMBER:metric_value:float} %{GREEDYDATA:extra_info}" 
      }
    }
    
    mutate { add_tag => ["metric"] }
    
    # Calculate moving averages
    if [metric_name] == "response_time" {
      aggregate {
        task_id => "%{[fields][service]}-response-time"
        code => "
          map['count'] ||= 0
          map['sum'] ||= 0.0
          map['count'] += 1
          map['sum'] += event.get('metric_value')
          event.set('avg_response_time', map['sum'] / map['count'])
        "
        push_map_as_event_on_timeout => true
        timeout => 60
        inactivity_timeout => 30
        timeout_tags => ['aggregated_metric']
      }
    }
  }
  
  # Business logic processing
  if [fields][service] == "ecommerce" and [message] =~ /ORDER_CREATED/ {
    grok {
      match => { 
        "message" => "ORDER_CREATED order_id=%{WORD:order_id} user_id=%{WORD:user_id} amount=%{NUMBER:amount:float}" 
      }
    }
    
    mutate { add_tag => ["business_event", "order"] }
    
    # Fraud detection logic
    ruby {
      code => '
        amount = event.get("amount")
        if amount > 10000
          event.set("fraud_risk", "high")
        elsif amount > 1000
          event.set("fraud_risk", "medium")
        else
          event.set("fraud_risk", "low")
        end
      '
    }
  }
}

output {
  if "metric" in [tags] {
    elasticsearch {
      hosts => ["es-metrics:9200"]
      index => "metrics-%{metric_name}-%{+YYYY.MM}"
    }
    
    # Send to time-series database
    influxdb {
      host => "influxdb"
      port => 8086
      database => "application_metrics"
      measurement => "%{metric_name}"
      send_as_tags => ["host", "service"]
      coerce_values => {
        "metric_value" => "float"
      }
    }
  }
  
  if "business_event" in [tags] {
    elasticsearch {
      hosts => ["es-business:9200"]
      index => "business-events-%{+YYYY.MM.dd}"
    }
    
    # High-risk orders
    if [fraud_risk] == "high" {
      http {
        url => "https://fraud-detection-service/api/alerts"
        http_method => "post"
        format => "json"
        mapping => {
          "order_id" => "%{order_id}"
          "user_id" => "%{user_id}"
          "amount" => "%{amount}"
          "risk_level" => "%{fraud_risk}"
          "timestamp" => "%{@timestamp}"
        }
      }
    }
  }
}
```

## 24. Production Deployment Strategy

### High Availability Setup
```yaml
# Load balancer configuration cho Logstash
# /etc/nginx/conf.d/logstash-lb.conf
upstream logstash_backend {
    least_conn;
    server logstash1:5044 max_fails=3 fail_timeout=30s;
    server logstash2:5044 max_fails=3 fail_timeout=30s;
    server logstash3:5044 max_fails=3 fail_timeout=30s;
}

server {
    listen 5044;
    proxy_pass logstash_backend;
    proxy_timeout 1s;
    proxy_responses 1;
    error_log /var/log/nginx/logstash-lb.log;
}
```

```yaml
# Filebeat config cho HA setup
output.logstash:
  hosts: ["lb-logstash:5044"]
  compression_level: 3
  bulk_max_size: 2048
  slow_start: true
  
  # Retry và timeout settings
  max_retries: 3
  backoff.init: 1s
  backoff.max: 60s
  timeout: 30s
  
  # TLS settings
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/ssl/certs/ca.pem"]
  ssl.verification_mode: certificate
```

### Docker Compose Production Setup
```yaml
# docker-compose.production.yml
version: '3.8'
services:
  filebeat:
    image: docker.elastic.co/beats/filebeat:8.11.0
    user: root
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log:/var/log:ro
      - filebeat-data:/usr/share/filebeat/data
    environment:
      - LOGSTASH_HOSTS=logstash1:5044,logstash2:5044
    depends_on:
      - logstash1
      - logstash2
    networks:
      - elk
    restart: unless-stopped

  logstash1:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - logstash1-data:/usr/share/logstash/data
    ports:
      - "5044:5044"
    environment:
      - LS_JAVA_OPTS=-Xms2g -Xmx2g
      - ELASTICSEARCH_HOSTS=elasticsearch1:9200,elasticsearch2:9200
    depends_on:
      - elasticsearch1
      - elasticsearch2
    networks:
      - elk
    restart: unless-stopped

  logstash2:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - logstash2-data:/usr/share/logstash/data
    ports:
      - "5045:5044"
    environment:
      - LS_JAVA_OPTS=-Xms2g -Xmx2g
      - ELASTICSEARCH_HOSTS=elasticsearch1:9200,elasticsearch2:9200
    depends_on:
      - elasticsearch1
      - elasticsearch2
    networks:
      - elk
    restart: unless-stopped

volumes:
  filebeat-data:
  logstash1-data:
  logstash2-data:

networks:
  elk:
    driver: bridge
```

### Scaling Strategy
```bash
#!/bin/bash
# auto-scale-logstash.sh
# Script để auto-scale Logstash instances

LOGSTASH_API="http://logstash:9600"
THRESHOLD_EVENTS_PER_SECOND=1000
SCALE_UP_THRESHOLD=0.8
SCALE_DOWN_THRESHOLD=0.3

# Get current metrics
CURRENT_EPS=$(curl -s "${LOGSTASH_API}/_node/stats/events" | jq '.events.in')
CURRENT_LOAD=$(echo "scale=2; $CURRENT_EPS / $THRESHOLD_EVENTS_PER_SECOND" | bc)

if (( $(echo "$CURRENT_LOAD > $SCALE_UP_THRESHOLD" | bc -l) )); then
    echo "Scaling up Logstash - Current load: $CURRENT_LOAD"
    docker service scale logstash=+1
elif (( $(echo "$CURRENT_LOAD < $SCALE_DOWN_THRESHOLD" | bc -l) )); then
    echo "Scaling down Logstash - Current load: $CURRENT_LOAD"
    docker service scale logstash=-1
fi
```

## 25. Best Practices cho ELK Stack

### Filebeat Best Practices
- Sử dụng SSD để lưu registry data
- Enable multiline processing cho stack traces
- Sử dụng processors để giảm tải cho Logstash
- Monitor harvester lag thường xuyên
- Sử dụng load balancing cho multiple Logstash instances
- Set appropriate close_inactive và clean_inactive values
- Use compression để giảm bandwidth

### Logstash Best Practices
- Tối ưu JVM heap size (50% RAM, max 32GB)
- Sử dụng persistent queue cho production
- Implement proper error handling với DLQ
- Use grok debugger để test patterns
- Monitor pipeline performance metrics
- Implement dead letter queue để handle failures
- Use multiple pipelines cho different data types
- Optimize filter order (cheap filters first)

### Security Best Practices
- Luôn sử dụng TLS cho tất cả connections
- Implement proper authentication và authorization
- Regular update tất cả components
- Use dedicated users với minimum permissions
- Encrypt sensitive data trong configs
- Implement network segmentation
- Use API keys thay vì passwords khi có thể
- Monitor access logs và failed authentication attempts

### Performance Optimization
```yaml
# Filebeat optimization
queue.mem:
  events: 4096
  flush.min_events: 1024
  flush.timeout: 1s

output.logstash:
  worker: 2
  bulk_max_size: 2048
  compression_level: 3
  slow_start: true
  ttl: 60s
  pipelining: 2

# Logstash optimization
pipeline.workers: 4
pipeline.batch.size: 1000
pipeline.batch.delay: 50
queue.type: persisted
queue.max_events: 1000000
queue.max_bytes: 1gb
```

### Monitoring và Alerting
```yaml
# Monitoring configuration
monitoring:
  enabled: true
  collection.enabled: true
  collection.interval: 10s
  
# Alert conditions to monitor:
# - Filebeat harvester lag > 60s
# - Logstash pipeline throughput < expected
# - Elasticsearch cluster health != green
# - Disk space < 10% free
# - Memory usage > 85%
# - Failed authentication attempts
```

## 26. Ví dụ thực tế End-to-End

### Multi-environment setup với Filebeat → Logstash → Elasticsearch
```yaml
# filebeat-production.yml
filebeat.inputs:
- type: log
  paths: ["/var/log/nginx/access.log"]
  fields:
    logtype: nginx_access
    env: production
    datacenter: us-east-1
  fields_under_root: true

- type: log
  paths: ["/var/log/app/*.log"]
  fields:
    logtype: application
    env: production
    service: webapp
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_docker_metadata:
    host: "unix:///var/run/docker.sock"

output.logstash:
  hosts: ["logstash-lb:5044"]
  loadbalance: true
  compression_level: 3
  bulk_max_size: 2048

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
```

```ruby
# /etc/logstash/conf.d/production.conf
input {
  beats {
    port => 5044
    include_codec_tag => false
  }
}

filter {
  # Add processing timestamp
  mutate {
    add_field => { "processed_at" => "%{@timestamp}" }
    add_field => { "logstash_node" => "${HOSTNAME}" }
  }
  
  if [logtype] == "nginx_access" {
    grok {
      match => { "message" => "%{NGINXACCESS}" }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    # GeoIP lookup
    if [clientip] and [clientip] !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))/ {
      geoip {
        source => "clientip"
        target => "geoip"
        fields => ["city_name", "country_name", "location", "region_name"]
      }
    }
    
    # User agent parsing
    if [agent] {
      useragent {
        source => "agent"
        target => "user_agent"
      }
    }
    
    # Response time classification
    if [response_time] {
      mutate { convert => { "response_time" => "float" } }
      
      if [response_time] > 5.0 {
        mutate { add_tag => ["slow_response", "performance_issue"] }
      } elsif [response_time] > 2.0 {
        mutate { add_tag => ["medium_response"] }
      } else {
        mutate { add_tag => ["fast_response"] }
      }
    }
    
    # Status code classification
    if [response] {
      mutate { convert => { "response" => "integer" } }
      
      if [response] >= 500 {
        mutate { add_tag => ["server_error", "alert"] }
      } elsif [response] >= 400 {
        mutate { add_tag => ["client_error"] }
      } elsif [response] >= 300 {
        mutate { add_tag => ["redirect"] }
      } else {
        mutate { add_tag => ["success"] }
      }
    }
    
  } else if [logtype] == "application" {
    # Application logs are already JSON
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Log level processing
    if [level] {
      mutate { uppercase => ["level"] }
      
      if [level] == "ERROR" {
        mutate { add_tag => ["error", "alert"] }
      } elsif [level] == "WARN" {
        mutate { add_tag => ["warning"] }
      } elsif [level] == "DEBUG" {
        mutate { add_tag => ["debug"] }
      }
    }
    
    # Database query performance
    if [sql_duration] {
      mutate { convert => { "sql_duration" => "float" } }
      if [sql_duration] > 1000 {
        mutate { add_tag => ["slow_query", "performance_issue"] }
      }
    }
    
    # API response time
    if [api_response_time] {
      mutate { convert => { "api_response_time" => "float" } }
      if [api_response_time] > 2000 {
        mutate { add_tag => ["slow_api", "performance_issue"] }
      }
    }
  }
  
  # Data sanitization
  if [message] {
    mutate {
      gsub => [
        "message", "password=[^&\s]+", "password=***",
        "message", "token=[^&\s]+", "token=***",
        "message", "apikey=[^&\s]+", "apikey=***"
      ]
    }
  }
  
  # Remove processed message field for nginx logs
  if [logtype] == "nginx_access" and [request] {
    mutate { remove_field => ["message"] }
  }
}

output {
  # Main storage
  elasticsearch {
    hosts => ["${ELASTICSEARCH_HOSTS}"]
    index => "%{env}-%{logtype}-%{+YYYY.MM.dd}"
    template_name => "production-logs"
    template_pattern => "production-*"
  }
  
  # Error alerts
  if "alert" in [tags] {
    elasticsearch {
      hosts => ["${ELASTICSEARCH_HOSTS}"]
      index => "alerts-%{+YYYY.MM.dd}"
    }
    
    # Send to monitoring system
    http {
      url => "${ALERT_WEBHOOK_URL}"
      http_method => "post"
      format => "json"
      headers => {
        "Content-Type" => "application/json"
        "Authorization" => "Bearer ${ALERT_TOKEN}"
      }
      mapping => {
        "alert_type" => "application_error"
        "severity" => "high"
        "source" => "%{host}"
        "service" => "%{service}"
        "environment" => "%{env}"
        "message" => "%{message}"
        "timestamp" => "%{@timestamp}"
        "tags" => "%{tags}"
      }
    }
  }
  
  # Performance issues
  if "performance_issue" in [tags] {
    elasticsearch {
      hosts => ["${ELASTICSEARCH_HOSTS}"]
      index => "performance-issues-%{+YYYY.MM.dd}"
    }
  }
  
  # Metrics to time-series DB
  if [response_time] or [sql_duration] or [api_response_time] {
    influxdb {
      host => "${INFLUXDB_HOST}"
      port => 8086
      database => "application_metrics"
      measurement => "performance"
      send_as_tags => ["host", "service", "env", "logtype"]
      coerce_values => {
        "response_time" => "float"
        "sql_duration" => "float"
        "api_response_time" => "float"
      }
    }
  }
}
```

Đây là tài liệu hoàn chỉnh về Filebeat và Logstash, từ cài đặt cơ bản đến triển khai production với high availability, monitoring và best practices. Tài liệu này cung cấp tất cả kiến thức cần thiết để xây dựng và vận hành một hệ thống log processing professional.200", "elasticsearch2:9200"]
    index => "logstash-%{[fields][logtype]}-%{+YYYY.MM.dd}"
    template_name => "logstash"
    template_pattern => "logstash-*"
    document_type => "_doc"
    
    # Authentication
    user => "logstash_writer"
    password => "password"
    
    # SSL/TLS
    ssl => true
    cacert => "/etc/ssl/certs/ca.pem"
  }
}
```

### File Output
```ruby
output {
  file {
    path => "/var/log/processed/logstash-%{+YYYY-MM-dd}.log"
    codec => json_lines
  }
}
```

### Kafka Output
```ruby
output {
  kafka {
    bootstrap_servers => "kafka1:9092,kafka2:9092"
    topic_id => "processed-logs"
    codec => json
  }
}
```

### Multiple Outputs (Conditional)
```ruby
output {
  if "error" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "error-logs-%{+YYYY.MM.dd}"
    }
    
    email {
      to => "admin@company.com"
      subject => "Error Alert: %{[host]}"
      body => "%{message}"
    }
  } else {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "general-logs-%{+YYYY.MM.dd}"
    }
  }
}
```

## 18. Ví dụ Pipeline hoàn chỉnh

### Apache Log Processing
```ruby
# /etc/logstash/conf.d/apache.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][logtype] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    if [clientip] {
      geoip {
        source => "clientip"
        target => "geoip"
      }
    }
    
    if [agent] {
      useragent {
        source => "agent"
        target => "useragent"
      }
    }
    
    mutate {
      convert => { "response" => "integer" }
      convert => { "bytes" => "integer" }
      remove_field => ["message"]
    }
    
    if [response] >= 400 {
      mutate {
        add_tag => ["error"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "apache-logs-%{+YYYY.MM.dd}"
  }
  
  if "error" in [tags] {
    file {
      path => "/var/log/apache-errors.log"
      codec => json_lines
    }
  }
}
```

### JSON Application Logs
```ruby
# /etc/logstash/conf.d/app.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][logtype] == "application" {
    json {
      source => "message"
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [level] == "ERROR" {
      mutate {
        add_tag => ["error", "alert"]
      }
    }
    
    if [user_id] {
      mutate {
        add_field => { "has_user" => "true" }
      }
    }
    
    ruby {
      code => '
        if event.get("response_time")
          rt = event.get("response_time").to_f
          if rt > 1000
            event.set("slow_query", true)
          end
        end
      '
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "app-logs-%{+YYYY.MM.dd}"
  }
}
```

## 19. Custom Grok Patterns và Performance Tuning

### Custom Grok Patterns
```ruby
# Tạo file custom patterns: /etc/logstash/patterns/custom
# /etc/logstash/patterns/custom
MYAPP_TIMESTAMP %{YEAR}-%{MONTHNUM}-%{MONTHDAY} %{TIME}
MYAPP_LOG %{MYAPP_TIMESTAMP:timestamp} \[%{LOGLEVEL:level}\] %{GREEDYDATA:message}

# Sử dụng trong config
filter {
  grok {
    patterns_dir => ["/etc/logstash/patterns"]
    match => { "message" => "%{MYAPP_LOG}" }
  }
}
```

### Performance Tuning cho Logstash

#### JVM Heap Settings
```bash
# /etc/logstash/jvm.options
-Xms2g
-Xmx2g
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200
-XX:+UseStringDeduplication
```

#### Pipeline Settings
```yaml
# logstash.yml
pipeline.workers: 4
pipeline.batch.size: 1000
pipeline.batch.delay: 50
pipeline.unsafe_shutdown: false
queue.type: persisted
path.queue: /var/lib/logstash/queue
queue.max_events: 1000000
queue.max_bytes: 1gb
```

#### Monitoring Pipeline Performance
```ruby
# Add trong output để monitor
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
    
    # Monitoring performance
    manage_template => false
    document_id => "%{fingerprint}"
  }
  
  # Monitor metrics
  statsd {
    host => "localhost"
    port => 8125
    increment => ["logstash.events.processed"]
  }
}
```

### Dead Letter Queue (DLQ)
```yaml
# logstash.yml
dead_letter_queue.enable: true
path.dead_letter_queue: /var/lib/logstash/dead_letter_queue
dead_letter_queue.max_bytes: 1gb
```

```ruby
# Process DLQ
input {
  dead_letter_queue {
    path => "/var/lib/logstash/dead_letter_queue"
    pipeline_id => "main"
  }
}
```

## 20. Tích hợp Filebeat với Logstash

### Cấu hình Filebeat gửi đến Logstash
```yaml
# filebeat.yml
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

- type: log
  enabled: true
  paths:
    - /var/log/myapp/*.log
  fields:
    logtype: application
    service: myapp
  fields_under_root: true
  multiline.pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
  multiline.negate: true
  multiline.match: after

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded

output.logstash:
  hosts: ["logstash1:5044", "logstash2:5044"]
  loadbalance: true
  compression_level: 3
  
setup.template.enabled: false
setup.ilm.enabled: false
```

### Cấu hình Logstash nhận từ Filebeat
```ruby
# /etc/logstash/conf.d/beats-input.conf
input {
  beats {
    port => 5044
    include_codec_tag => false
    congestion_threshold => 40
    target_field_for_codec => "[@metadata][codec]"
  }
}

filter {
  # Xử lý theo logtype từ Filebeat
  if [logtype] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    geoip {
      source => "clientip"
      target => "geoip"
    }
    
  } else if [logtype] == "application" {
    json {
      source => "message"
    }
    
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
  }
  
  # Thêm metadata
  mutate {
    add_field => { "processed_by" => "logstash" }
    add_field => { "processed_at" => "%{@timestamp}" }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch1:9