# Prometheus Alert Rules cho Logging Stack trên Kubernetes

## Tổng quan kiến trúc
- **Filebeat**: Thu thập logs từ pods
- **Kafka**: Message queue trung gian
- **Logstash**: Xử lý và transform logs
- **OpenSearch**: Lưu trữ và tìm kiếm logs
- **OpenSearch Dashboard**: Visualization
- **AKHQ**: Kafka monitoring UI

---

## 1. Filebeat Monitoring Rules

### 1.1 Filebeat Pod Availability
```yaml
- alert: FilebeatPodDown
  expr: up{job="filebeat"} == 0
  for: 5m
  labels:
    severity: critical
    component: filebeat
  annotations:
    summary: "Filebeat pod is down"
    description: "Filebeat pod {{ $labels.instance }} has been down for more than 5 minutes"
```

### 1.2 Filebeat Events Processing
```yaml
- alert: FilebeatEventsDropped
  expr: rate(filebeat_events_dropped_total[5m]) > 100
  for: 10m
  labels:
    severity: warning
    component: filebeat
  annotations:
    summary: "Filebeat dropping events"
    description: "Filebeat on {{ $labels.instance }} is dropping events at rate {{ $value }} events/sec"

- alert: FilebeatHighPublishFailures
  expr: rate(filebeat_libbeat_output_events_failed_total[5m]) > 10
  for: 10m
  labels:
    severity: warning
    component: filebeat
  annotations:
    summary: "Filebeat high publish failures"
    description: "Filebeat {{ $labels.instance }} has high publish failure rate: {{ $value }}/sec"
```

### 1.3 Filebeat Resource Usage
```yaml
- alert: FilebeatHighMemoryUsage
  expr: container_memory_usage_bytes{container="filebeat"} / container_spec_memory_limit_bytes{container="filebeat"} > 0.85
  for: 15m
  labels:
    severity: warning
    component: filebeat
  annotations:
    summary: "Filebeat high memory usage"
    description: "Filebeat pod {{ $labels.pod }} is using {{ $value | humanizePercentage }} of memory limit"

- alert: FilebeatHighCPUUsage
  expr: rate(container_cpu_usage_seconds_total{container="filebeat"}[5m]) > 0.8
  for: 15m
  labels:
    severity: warning
    component: filebeat
  annotations:
    summary: "Filebeat high CPU usage"
    description: "Filebeat pod {{ $labels.pod }} CPU usage is {{ $value | humanizePercentage }}"
```

---

## 2. Kafka Monitoring Rules

### 2.1 Kafka Broker Availability
```yaml
- alert: KafkaBrokerDown
  expr: kafka_server_replicamanager_leadercount == 0
  for: 5m
  labels:
    severity: critical
    component: kafka
  annotations:
    summary: "Kafka broker is down"
    description: "Kafka broker {{ $labels.instance }} has no leaders, possibly down"

- alert: KafkaClusterUnderReplicated
  expr: kafka_server_replicamanager_underreplicatedpartitions > 0
  for: 10m
  labels:
    severity: critical
    component: kafka
  annotations:
    summary: "Kafka cluster has under-replicated partitions"
    description: "Kafka cluster has {{ $value }} under-replicated partitions on {{ $labels.instance }}"
```

### 2.2 Kafka Performance
```yaml
- alert: KafkaHighProducerRequestRate
  expr: rate(kafka_network_requestmetrics_requests_total{request="Produce"}[5m]) > 10000
  for: 10m
  labels:
    severity: warning
    component: kafka
  annotations:
    summary: "High Kafka producer request rate"
    description: "Kafka broker {{ $labels.instance }} has high producer request rate: {{ $value }}/sec"

- alert: KafkaHighConsumerLag
  expr: kafka_consumergroup_lag > 10000
  for: 10m
  labels:
    severity: warning
    component: kafka
  annotations:
    summary: "High consumer lag detected"
    description: "Consumer group {{ $labels.consumergroup }} has lag of {{ $value }} messages on topic {{ $labels.topic }}"

- alert: KafkaOfflinePartitions
  expr: kafka_controller_kafkacontroller_offlinepartitionscount > 0
  for: 5m
  labels:
    severity: critical
    component: kafka
  annotations:
    summary: "Kafka has offline partitions"
    description: "Kafka cluster has {{ $value }} offline partitions"
```

### 2.3 Kafka Disk Usage
```yaml
- alert: KafkaDiskUsageHigh
  expr: (kafka_log_log_size / kafka_log_log_size_limit) > 0.85
  for: 15m
  labels:
    severity: warning
    component: kafka
  annotations:
    summary: "Kafka disk usage high"
    description: "Kafka broker {{ $labels.instance }} disk usage is {{ $value | humanizePercentage }}"

- alert: KafkaDiskUsageCritical
  expr: (kafka_log_log_size / kafka_log_log_size_limit) > 0.95
  for: 5m
  labels:
    severity: critical
    component: kafka
  annotations:
    summary: "Kafka disk usage critical"
    description: "Kafka broker {{ $labels.instance }} disk usage is {{ $value | humanizePercentage }}"
```

---

## 3. Logstash Monitoring Rules

### 3.1 Logstash Pipeline Health
```yaml
- alert: LogstashPodDown
  expr: up{job="logstash"} == 0
  for: 5m
  labels:
    severity: critical
    component: logstash
  annotations:
    summary: "Logstash pod is down"
    description: "Logstash pod {{ $labels.instance }} has been down for more than 5 minutes"

- alert: LogstashPipelineFailures
  expr: rate(logstash_pipeline_events_out_total[5m]) == 0 and rate(logstash_pipeline_events_in_total[5m]) > 0
  for: 10m
  labels:
    severity: critical
    component: logstash
  annotations:
    summary: "Logstash pipeline not processing events"
    description: "Logstash {{ $labels.instance }} pipeline {{ $labels.pipeline }} is receiving events but not outputting any"
```

### 3.2 Logstash Performance
```yaml
- alert: LogstashHighEventLatency
  expr: logstash_pipeline_events_duration_seconds > 10
  for: 10m
  labels:
    severity: warning
    component: logstash
  annotations:
    summary: "Logstash high event processing latency"
    description: "Logstash {{ $labels.instance }} pipeline {{ $labels.pipeline }} has latency of {{ $value }}s"

- alert: LogstashQueueFull
  expr: (logstash_pipeline_queue_events / logstash_pipeline_queue_max_size_in_bytes) > 0.90
  for: 10m
  labels:
    severity: warning
    component: logstash
  annotations:
    summary: "Logstash queue nearly full"
    description: "Logstash {{ $labels.instance }} queue is {{ $value | humanizePercentage }} full"
```

### 3.3 Logstash Resource Usage
```yaml
- alert: LogstashHighMemoryUsage
  expr: container_memory_usage_bytes{container="logstash"} / container_spec_memory_limit_bytes{container="logstash"} > 0.85
  for: 15m
  labels:
    severity: warning
    component: logstash
  annotations:
    summary: "Logstash high memory usage"
    description: "Logstash pod {{ $labels.pod }} memory usage is {{ $value | humanizePercentage }}"

- alert: LogstashHighCPUUsage
  expr: rate(container_cpu_usage_seconds_total{container="logstash"}[5m]) > 0.85
  for: 15m
  labels:
    severity: warning
    component: logstash
  annotations:
    summary: "Logstash high CPU usage"
    description: "Logstash pod {{ $labels.pod }} CPU usage is {{ $value | humanizePercentage }}"
```

---

## 4. OpenSearch Monitoring Rules

### 4.1 OpenSearch Cluster Health
```yaml
- alert: OpenSearchClusterRed
  expr: opensearch_cluster_health_status{color="red"} == 1
  for: 5m
  labels:
    severity: critical
    component: opensearch
  annotations:
    summary: "OpenSearch cluster status is RED"
    description: "OpenSearch cluster {{ $labels.cluster }} is in RED state"

- alert: OpenSearchClusterYellow
  expr: opensearch_cluster_health_status{color="yellow"} == 1
  for: 30m
  labels:
    severity: warning
    component: opensearch
  annotations:
    summary: "OpenSearch cluster status is YELLOW"
    description: "OpenSearch cluster {{ $labels.cluster }} has been YELLOW for 30+ minutes"

- alert: OpenSearchNodeDown
  expr: up{job="opensearch"} == 0
  for: 5m
  labels:
    severity: critical
    component: opensearch
  annotations:
    summary: "OpenSearch node is down"
    description: "OpenSearch node {{ $labels.instance }} is down"
```

### 4.2 OpenSearch Performance
```yaml
- alert: OpenSearchHighIndexingLatency
  expr: opensearch_index_indexing_index_time_seconds / opensearch_index_indexing_index_total > 0.5
  for: 10m
  labels:
    severity: warning
    component: opensearch
  annotations:
    summary: "High indexing latency in OpenSearch"
    description: "OpenSearch node {{ $labels.node }} has indexing latency of {{ $value }}s per document"

- alert: OpenSearchHighSearchLatency
  expr: rate(opensearch_index_search_query_time_seconds[5m]) / rate(opensearch_index_search_query_total[5m]) > 1
  for: 10m
  labels:
    severity: warning
    component: opensearch
  annotations:
    summary: "High search latency in OpenSearch"
    description: "OpenSearch node {{ $labels.node }} has search latency of {{ $value }}s per query"

- alert: OpenSearchHighRejectedThreads
  expr: rate(opensearch_thread_pool_rejected_count[5m]) > 10
  for: 10m
  labels:
    severity: warning
    component: opensearch
  annotations:
    summary: "OpenSearch rejecting thread pool tasks"
    description: "OpenSearch node {{ $labels.node }} is rejecting {{ $value }} tasks/sec on {{ $labels.name }} thread pool"
```

### 4.3 OpenSearch Storage
```yaml
- alert: OpenSearchDiskSpaceHigh
  expr: (1 - (opensearch_filesystem_data_available_bytes / opensearch_filesystem_data_size_bytes)) > 0.85
  for: 15m
  labels:
    severity: warning
    component: opensearch
  annotations:
    summary: "OpenSearch disk space usage high"
    description: "OpenSearch node {{ $labels.node }} disk usage is {{ $value | humanizePercentage }}"

- alert: OpenSearchDiskSpaceCritical
  expr: (1 - (opensearch_filesystem_data_available_bytes / opensearch_filesystem_data_size_bytes)) > 0.95
  for: 5m
  labels:
    severity: critical
    component: opensearch
  annotations:
    summary: "OpenSearch disk space critical"
    description: "OpenSearch node {{ $labels.node }} disk usage is {{ $value | humanizePercentage }}"
```

### 4.4 OpenSearch JVM
```yaml
- alert: OpenSearchHighJVMMemoryUsage
  expr: opensearch_jvm_mem_heap_used_percent > 85
  for: 15m
  labels:
    severity: warning
    component: opensearch
  annotations:
    summary: "OpenSearch high JVM memory usage"
    description: "OpenSearch node {{ $labels.node }} JVM heap usage is {{ $value }}%"

- alert: OpenSearchHighGCTime
  expr: rate(opensearch_jvm_gc_collection_time_seconds[5m]) > 0.5
  for: 10m
  labels:
    severity: warning
    component: opensearch
  annotations:
    summary: "OpenSearch high GC time"
    description: "OpenSearch node {{ $labels.node }} is spending {{ $value }}s/sec in GC"
```

---

## 5. OpenSearch Dashboard Monitoring Rules

### 5.1 Dashboard Availability
```yaml
- alert: OpenSearchDashboardDown
  expr: up{job="opensearch-dashboards"} == 0
  for: 5m
  labels:
    severity: critical
    component: opensearch-dashboards
  annotations:
    summary: "OpenSearch Dashboard is down"
    description: "OpenSearch Dashboard {{ $labels.instance }} has been down for 5+ minutes"

- alert: OpenSearchDashboardHighResponseTime
  expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="opensearch-dashboards"}[5m])) > 5
  for: 10m
  labels:
    severity: warning
    component: opensearch-dashboards
  annotations:
    summary: "OpenSearch Dashboard slow response"
    description: "OpenSearch Dashboard {{ $labels.instance }} 95th percentile response time is {{ $value }}s"
```

### 5.2 Dashboard Resources
```yaml
- alert: OpenSearchDashboardHighMemoryUsage
  expr: container_memory_usage_bytes{container="opensearch-dashboards"} / container_spec_memory_limit_bytes{container="opensearch-dashboards"} > 0.85
  for: 15m
  labels:
    severity: warning
    component: opensearch-dashboards
  annotations:
    summary: "OpenSearch Dashboard high memory usage"
    description: "Dashboard pod {{ $labels.pod }} memory usage is {{ $value | humanizePercentage }}"
```

---

## 6. AKHQ Monitoring Rules

### 6.1 AKHQ Availability
```yaml
- alert: AKHQDown
  expr: up{job="akhq"} == 0
  for: 5m
  labels:
    severity: warning
    component: akhq
  annotations:
    summary: "AKHQ is down"
    description: "AKHQ instance {{ $labels.instance }} is not responding"

- alert: AKHQHighResponseTime
  expr: histogram_quantile(0.95, rate(http_server_requests_seconds_bucket{job="akhq"}[5m])) > 3
  for: 10m
  labels:
    severity: warning
    component: akhq
  annotations:
    summary: "AKHQ slow response time"
    description: "AKHQ {{ $labels.instance }} 95th percentile response time is {{ $value }}s"
```

---

## 7. Kubernetes Generic Rules

### 7.1 Pod Status
```yaml
- alert: PodCrashLooping
  expr: rate(kube_pod_container_status_restarts_total{namespace=~"logging.*"}[15m]) > 0
  for: 15m
  labels:
    severity: critical
    component: kubernetes
  annotations:
    summary: "Pod is crash looping"
    description: "Pod {{ $labels.namespace }}/{{ $labels.pod }} is crash looping"

- alert: PodNotReady
  expr: sum by (namespace, pod) (kube_pod_status_phase{phase=~"Pending|Unknown|Failed", namespace=~"logging.*"}) > 0
  for: 15m
  labels:
    severity: warning
    component: kubernetes
  annotations:
    summary: "Pod not ready"
    description: "Pod {{ $labels.namespace }}/{{ $labels.pod }} has been in {{ $labels.phase }} state for 15+ minutes"
```

### 7.2 PVC Issues
```yaml
- alert: PersistentVolumeClaimPending
  expr: kube_persistentvolumeclaim_status_phase{phase="Pending", namespace=~"logging.*"} == 1
  for: 10m
  labels:
    severity: warning
    component: kubernetes
  annotations:
    summary: "PVC pending"
    description: "PVC {{ $labels.namespace }}/{{ $labels.persistentvolumeclaim }} is pending"

- alert: PersistentVolumeSpaceHigh
  expr: (kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes) > 0.85
  for: 15m
  labels:
    severity: warning
    component: kubernetes
  annotations:
    summary: "PV space usage high"
    description: "PV {{ $labels.persistentvolumeclaim }} in {{ $labels.namespace }} is {{ $value | humanizePercentage }} full"
```

---

## 8. Cấu hình AlertManager

### 8.1 Example AlertManager Config
```yaml
global:
  resolve_timeout: 5m
  slack_api_url: 'YOUR_SLACK_WEBHOOK_URL'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      continue: true
    - match:
        severity: warning
      receiver: 'warning-alerts'

receivers:
  - name: 'default'
    slack_configs:
      - channel: '#logging-alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

  - name: 'critical-alerts'
    slack_configs:
      - channel: '#critical-alerts'
        title: 'CRITICAL: {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_KEY'

  - name: 'warning-alerts'
    slack_configs:
      - channel: '#logging-alerts'
        title: 'WARNING: {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'cluster', 'service']
```

---

## 9. ServiceMonitor Examples

### 9.1 Filebeat ServiceMonitor
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: filebeat
  namespace: logging
spec:
  selector:
    matchLabels:
      app: filebeat
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
```

### 9.2 Kafka ServiceMonitor
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kafka
  namespace: logging
spec:
  selector:
    matchLabels:
      app: kafka
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
```

### 9.3 OpenSearch ServiceMonitor
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: opensearch
  namespace: logging
spec:
  selector:
    matchLabels:
      app: opensearch
  endpoints:
    - port: metrics
      interval: 30s
      path: /_prometheus/metrics
```

---

## 10. Best Practices

### 10.1 Alert Tuning
- **Đặt threshold phù hợp**: Dựa vào baseline của hệ thống production
- **Tránh alert storm**: Sử dụng inhibit rules để tắt các alert phụ thuộc
- **Group alerts**: Group theo service/component để dễ troubleshoot
- **Đặt for duration hợp lý**: Tránh false positive do spike tạm thời

### 10.2 Alert Severity Levels
- **Critical**: Cần xử lý ngay lập tức, ảnh hưởng đến service
- **Warning**: Cần theo dõi, có thể dẫn đến critical nếu không xử lý
- **Info**: Thông tin, không cần action ngay

### 10.3 Monitoring Checklist
- [ ] Enable metrics endpoints cho tất cả components
- [ ] Deploy ServiceMonitors trong Kubernetes
- [ ] Configure AlertManager với notification channels
- [ ] Test alerts bằng cách trigger manually
- [ ] Document runbooks cho mỗi alert
- [ ] Set up dashboards trong Grafana
- [ ] Configure retention policy cho Prometheus
- [ ] Backup alert rules và configs

### 10.4 Metrics Export Configuration

#### Filebeat metrics module
```yaml
# filebeat.yml
http.enabled: true
http.host: 0.0.0.0
http.port: 5066
```

#### Kafka JMX Exporter
```yaml
# Sử dụng kafka-exporter hoặc JMX exporter
# https://github.com/danielqsj/kafka_exporter
```

#### Logstash monitoring
```yaml
# logstash.yml
http.host: "0.0.0.0"
http.port: 9600
monitoring.enabled: true
```

#### OpenSearch metrics
```yaml
# OpenSearch tự động expose metrics tại /_prometheus/metrics
# Cần cấu hình trong opensearch.yml nếu cần customize
```

---

## 11. Dashboards Recommendations

### 11.1 Grafana Dashboards
- **Kafka Overview**: Dashboard ID 7589
- **OpenSearch**: Dashboard ID 10484
- **Kubernetes Cluster Monitoring**: Dashboard ID 7249
- **Node Exporter Full**: Dashboard ID 1860

### 11.2 Custom Metrics to Track
- Log ingestion rate (events/sec)
- End-to-end latency (Filebeat → OpenSearch)
- Kafka consumer lag per topic
- OpenSearch query performance
- Storage growth rate
- Error rates per component

---

## 12. Hướng dẫn kiểm tra metrics trên Prometheus GUI

### 12.0 Truy cập Prometheus GUI

#### Port-forward để truy cập Prometheus
```bash
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090
```
Sau đó truy cập: **http://localhost:9090**

#### Các tab quan trọng trong Prometheus GUI:
- **Graph**: Tab chính để query và visualize metrics
- **Targets**: Xem trạng thái các targets đang được scrape
- **Alerts**: Xem các alert rules và trạng thái
- **Service Discovery**: Xem các services được discover

---

### 12.1 Kiểm tra Targets (Bước đầu tiên - QUAN TRỌNG)

**Truy cập**: Status → Targets (http://localhost:9090/targets)

✅ **Cần kiểm tra các targets sau đang UP:**
- `filebeat` - State: UP
- `kafka` hoặc `kafka-exporter` - State: UP  
- `logstash` - State: UP
- `opensearch` - State: UP
- `opensearch-dashboards` - State: UP
- `akhq` - State: UP
- `kube-state-metrics` - State: UP (cho Kubernetes metrics)

❌ **Nếu target DOWN:**
- Kiểm tra ServiceMonitor configuration
- Kiểm tra Service selector labels
- Kiểm tra pod có expose metrics port không
- Xem error message trong cột "Last Error"

---

### 12.2 Filebeat Metrics Verification

**Truy cập**: Graph tab (http://localhost:9090/graph)

#### 1. Kiểm tra Filebeat đang chạy
**Query trong ô Expression:**
```promql
up{job="filebeat"}
```
**Expected Result**: 
- Value = `1` cho mỗi Filebeat pod
- Nếu = `0` hoặc không có kết quả → Filebeat down hoặc không được scrape

#### 2. Xem tất cả Filebeat metrics available
```promql
{__name__=~"filebeat.*"}
```
**Cách xem**: Click "Graph" tab để xem time series, hoặc "Table" để xem giá trị hiện tại

#### 3. Kiểm tra events dropped (cho alert rule)
```promql
rate(filebeat_events_dropped_total[5m])
```
**Expected**: Giá trị nhỏ hoặc = 0 là tốt. Nếu > 100 events/sec thì có vấn đề

#### 4. Kiểm tra output failures
```promql
rate(filebeat_libbeat_output_events_failed_total[5m])
```
**Expected**: Giá trị gần 0 là tốt

#### 5. Kiểm tra memory usage (%)
```promql
container_memory_usage_bytes{container="filebeat"} / container_spec_memory_limit_bytes{container="filebeat"} * 100
```
**Expected**: < 85% là bình thường

#### 6. Kiểm tra CPU usage
```promql
rate(container_cpu_usage_seconds_total{container="filebeat"}[5m]) * 100
```
**Expected**: < 80% là bình thường

---

### 12.3 Kafka Metrics Verification

#### 1. Kiểm tra Kafka broker up
```promql
up{job=~"kafka.*"}
```
**Expected**: Value = 1 cho tất cả brokers

#### 2. Xem tất cả Kafka metrics
```promql
{__name__=~"kafka.*"}
```
**Note**: Có thể search trong Metrics Explorer (click vào biểu tượng metrics)

#### 3. Kiểm tra leader count (nên > 0)
```promql
kafka_server_replicamanager_leadercount
```
**Expected**: Mỗi broker có leaders > 0. Nếu = 0 → broker có vấn đề

#### 4. Kiểm tra under-replicated partitions
```promql
kafka_server_replicamanager_underreplicatedpartitions
```
**Expected**: = 0 là tốt. Nếu > 0 → có partition chưa được replicate đủ

#### 5. Kiểm tra offline partitions
```promql
kafka_controller_kafkacontroller_offlinepartitionscount
```
**Expected**: = 0. Nếu > 0 → CRITICAL, có partitions offline

#### 6. Kiểm tra consumer lag
```promql
kafka_consumergroup_lag
```
**Expected**: < 10000 messages. Nếu cao → consumer xử lý chậm

#### 7. Kiểm tra produce request rate
```promql
rate(kafka_network_requestmetrics_requests_total{request="Produce"}[5m])
```
**Expected**: Xem baseline normal của hệ thống

#### 8. Kiểm tra disk usage
```promql
(kafka_log_log_size / kafka_log_log_size_limit) * 100
```
**Expected**: < 85%

---

### 12.4 Logstash Metrics Verification

#### 1. Kiểm tra Logstash up
```promql
up{job="logstash"}
```
**Expected**: Value = 1

#### 2. Xem tất cả Logstash metrics
```promql
{__name__=~"logstash.*"}
```

#### 3. Kiểm tra events input rate
```promql
rate(logstash_pipeline_events_in_total[5m])
```
**Expected**: > 0 nếu có logs đang được gửi đến

#### 4. Kiểm tra events output rate
```promql
rate(logstash_pipeline_events_out_total[5m])
```
**Expected**: Tương đương với input rate. Nếu = 0 mà input > 0 → pipeline có lỗi

#### 5. Kiểm tra pipeline working (so sánh in vs out)
```promql
rate(logstash_pipeline_events_out_total[5m]) > 0 and rate(logstash_pipeline_events_in_total[5m]) > 0
```
**Expected**: Có kết quả = pipeline đang xử lý events

#### 6. Kiểm tra processing latency
```promql
logstash_pipeline_events_duration_seconds
```
**Expected**: < 10 seconds

#### 7. Kiểm tra queue fullness (%)
```promql
(logstash_pipeline_queue_events / logstash_pipeline_queue_max_size_in_bytes) * 100
```
**Expected**: < 90%

#### 8. Kiểm tra memory usage
```promql
container_memory_usage_bytes{container="logstash"} / container_spec_memory_limit_bytes{container="logstash"} * 100
```
**Expected**: < 85%

---

### 12.5 OpenSearch Metrics Verification

#### 1. Kiểm tra OpenSearch nodes up
```promql
up{job="opensearch"}
```
**Expected**: Value = 1 cho tất cả nodes

#### 2. Xem tất cả OpenSearch metrics
```promql
{__name__=~"opensearch.*"}
```

#### 3. Kiểm tra cluster health (QUAN TRỌNG)
```promql
opensearch_cluster_health_status
```
**Expected**: 
- `color="green"` = 1 → Cluster khỏe mạnh ✅
- `color="yellow"` = 1 → Warning, có replica issues ⚠️
- `color="red"` = 1 → Critical, có primary shards missing ❌

#### 4. Xem số nodes trong cluster
```promql
opensearch_cluster_health_number_of_nodes
```
**Expected**: Match với số nodes deployed

#### 5. Kiểm tra indexing latency (ms per document)
```promql
(opensearch_index_indexing_index_time_seconds / opensearch_index_indexing_index_total) * 1000
```
**Expected**: < 500ms per document

#### 6. Kiểm tra search latency (seconds per query)
```promql
rate(opensearch_index_search_query_time_seconds[5m]) / rate(opensearch_index_search_query_total[5m])
```
**Expected**: < 1 second

#### 7. Kiểm tra thread pool rejections
```promql
rate(opensearch_thread_pool_rejected_count[5m])
```
**Expected**: = 0 hoặc rất nhỏ. Nếu cao → cluster overload

#### 8. Kiểm tra disk usage (%)
```promql
(1 - (opensearch_filesystem_data_available_bytes / opensearch_filesystem_data_size_bytes)) * 100
```
**Expected**: < 85%

#### 9. Kiểm tra JVM heap usage (%)
```promql
opensearch_jvm_mem_heap_used_percent
```
**Expected**: < 85%. Nếu > 90% → risk of OOM

#### 10. Kiểm tra GC time (should be low)
```promql
rate(opensearch_jvm_gc_collection_time_seconds[5m])
```
**Expected**: < 0.1 seconds/sec (< 10% time in GC)

---

### 12.6 OpenSearch Dashboard Metrics Verification

#### 1. Kiểm tra Dashboard up
```promql
up{job="opensearch-dashboards"}
```
**Expected**: Value = 1

#### 2. Kiểm tra response time (nếu có metrics)
```promql
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="opensearch-dashboards"}[5m]))
```
**Expected**: < 5 seconds

#### 3. Kiểm tra memory usage
```promql
container_memory_usage_bytes{container="opensearch-dashboards"} / container_spec_memory_limit_bytes{container="opensearch-dashboards"} * 100
```
**Expected**: < 85%

---

### 12.7 AKHQ Metrics Verification

#### 1. Kiểm tra AKHQ up
```promql
up{job="akhq"}
```
**Expected**: Value = 1

#### 2. Kiểm tra response time
```promql
histogram_quantile(0.95, rate(http_server_requests_seconds_bucket{job="akhq"}[5m]))
```
**Expected**: < 3 seconds

---

### 12.8 Kubernetes Metrics Verification

#### 1. Kiểm tra pod restart count
```promql
kube_pod_container_status_restarts_total{namespace=~"logging.*"}
```
**Expected**: Giá trị không tăng liên tục

#### 2. Kiểm tra restart rate (trong 15 phút)
```promql
rate(kube_pod_container_status_restarts_total{namespace=~"logging.*"}[15m])
```
**Expected**: = 0 hoặc rất nhỏ

#### 3. Kiểm tra pod status
```promql
kube_pod_status_phase{namespace=~"logging.*"}
```
**Expected**: `phase="Running"` = 1 cho tất cả pods

#### 4. Xem pods NOT running
```promql
kube_pod_status_phase{namespace=~"logging.*", phase=~"Pending|Unknown|Failed"}
```
**Expected**: Không có kết quả

#### 5. Kiểm tra PVC status
```promql
kube_persistentvolumeclaim_status_phase{namespace=~"logging.*"}
```
**Expected**: `phase="Bound"` = 1

#### 6. Kiểm tra volume usage (%)
```promql
(kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes) * 100
```
**Expected**: < 85%

---

## 13. Checklist kiểm tra metrics trên Prometheus GUI

### 📋 Pre-deployment Checklist

In ra checklist này và tick ✅ khi kiểm tra xong mỗi mục:

#### **Bước 1: Kiểm tra Targets**
- [ ] Truy cập Status → Targets
- [ ] Target `filebeat` đang UP
- [ ] Target `kafka` hoặc `kafka-exporter` đang UP
- [ ] Target `logstash` đang UP
- [ ] Target `opensearch` đang UP
- [ ] Target `opensearch-dashboards` đang UP
- [ ] Target `akhq` đang UP
- [ ] Target `kube-state-metrics` đang UP

#### **Bước 2: Filebeat Metrics**
- [ ] Query `up{job="filebeat"}` return 1
- [ ] Query `{__name__=~"filebeat.*"}` có kết quả
- [ ] Query `rate(filebeat_events_dropped_total[5m])` hoạt động
- [ ] Query `container_memory_usage_bytes{container="filebeat"}` có data

#### **Bước 3: Kafka Metrics**
- [ ] Query `up{job=~"kafka.*"}` return 1
- [ ] Query `kafka_server_replicamanager_leadercount` có kết quả
- [ ] Query `kafka_server_replicamanager_underreplicatedpartitions` hoạt động
- [ ] Query `kafka_controller_kafkacontroller_offlinepartitionscount` có data
- [ ] Query `kafka_consumergroup_lag` (nếu có) hoạt động

#### **Bước 4: Logstash Metrics**
- [ ] Query `up{job="logstash"}` return 1
- [ ] Query `logstash_pipeline_events_in_total` có kết quả
- [ ] Query `logstash_pipeline_events_out_total` có kết quả
- [ ] Query `rate(logstash_pipeline_events_out_total[5m]) > 0` có data

#### **Bước 5: OpenSearch Metrics**
- [ ] Query `up{job="opensearch"}` return 1
- [ ] Query `opensearch_cluster_health_status` return green
- [ ] Query `opensearch_jvm_mem_heap_used_percent` có kết quả
- [ ] Query `opensearch_filesystem_data_available_bytes` có data

#### **Bước 6: Kubernetes Metrics**
- [ ] Query `kube_pod_container_status_restarts_total` có kết quả
- [ ] Query `kube_pod_status_phase{namespace=~"logging.*"}` có data
- [ ] Query `kubelet_volume_stats_used_bytes` hoạt động

#### **Bước 7: Alert Rules**
- [ ] Truy cập Alerts tab
- [ ] Có thấy các alert rules đã được load
- [ ] Không có alert nào đang Firing (hoặc có lý do rõ ràng)

---

## 14. Screenshot Guide - Cách test trên Prometheus GUI

### Test Case 1: Kiểm tra Filebeat đang hoạt động

**Bước 1:** Truy cập Graph tab
**Bước 2:** Nhập query:
```promql
up{job="filebeat"}
```
**Bước 3:** Click "Execute"
**Bước 4:** Xem kết quả:
```
✅ Tốt: Thấy value = 1 cho mỗi instance
❌ Lỗi: value = 0 hoặc "Empty query result"
```

### Test Case 2: Kiểm tra Filebeat có đang drop events không

**Query:**
```promql
rate(filebeat_events_dropped_total[5m])
```
**Kết quả mong đợi:**
```
✅ Tốt: Value = 0 hoặc rất nhỏ (< 1)
⚠️  Warning: Value > 1 và < 100
❌ Critical: Value > 100
```

### Test Case 3: Kiểm tra Kafka cluster health

**Query 1 - Broker up:**
```promql
up{job=~"kafka.*"}
```
**Expected:** Value = 1

**Query 2 - Under-replicated partitions:**
```promql
kafka_server_replicamanager_underreplicatedpartitions
```
**Expected:** Value = 0

**Query 3 - Offline partitions:**
```promql
kafka_controller_kafkacontroller_offlinepartitionscount
```
**Expected:** Value = 0

### Test Case 4: Kiểm tra Logstash pipeline

**Query 1 - Events flowing in:**
```promql
rate(logstash_pipeline_events_in_total[5m])
```
**Expected:** Value > 0 (nếu có logs)

**Query 2 - Events flowing out:**
```promql
rate(logstash_pipeline_events_out_total[5m])
```
**Expected:** Value tương đương với events in

**Query 3 - Pipeline stuck check:**
```promql
rate(logstash_pipeline_events_in_total[5m]) > 0 and rate(logstash_pipeline_events_out_total[5m]) == 0
```
**Expected:** Empty result (pipeline không bị stuck)

### Test Case 5: OpenSearch cluster health

**Query:**
```promql
opensearch_cluster_health_status
```
**Cách đọc kết quả:**
- Tìm label `color="green"`, value = 1 → ✅ Cluster khỏe
- Tìm label `color="yellow"`, value = 1 → ⚠️ Warning
- Tìm label `color="red"`, value = 1 → ❌ Critical

### Test Case 6: OpenSearch disk space

**Query:**
```promql
(1 - (opensearch_filesystem_data_available_bytes / opensearch_filesystem_data_size_bytes)) * 100
```
**Kết quả:**
```
✅ < 70%: Tốt
⚠️  70-85%: Cần theo dõi
❌ > 85%: Warning alert sẽ fire
🔥 > 95%: Critical alert sẽ fire
```

---

## 15. Troubleshooting trên Prometheus GUI

### ❌ Problem: "Empty query result"

**Nguyên nhân có thể:**
1. Metric không tồn tại
2. Label selector sai
3. Target không được scrape
4. Time range không có data

**Cách fix:**

**Step 1:** Kiểm tra Target
- Vào Status → Targets
- Tìm job tương ứng
- Xem State có phải UP không
- Xem Last Error (nếu có)

**Step 2:** Kiểm tra metric có tồn tại không
- Click vào biểu tượng "Metrics Explorer" (hình globe)
- Search metric name
- Nếu không thấy → metric không được export

**Step 3:** Test query đơn giản hơn
```promql
# Thay vì query phức tạp, test cơ bản trước
up{job="filebeat"}

# Nếu không work, thử không filter
up

# Xem tất cả jobs
up{job=~".*"}
```

**Step 4:** Kiểm tra time range
- Mở rộng time range (ví dụ: từ 1h → 3h)
- Click "Graph" tab để xem data có bị gaps không

### ❌ Problem: Query returns data nhưng alert không fire

**Nguyên nhân:**
- Alert rule chưa được load vào Prometheus
- Alert có `for` duration chưa đủ
- Alert đang bị inhibit

**Cách fix:**

**Step 1:** Kiểm tra Alert Rules
- Vào Alerts tab
- Search tên alert
- Xem State: Inactive / Pending / Firing

**Step 2:** Test alert expression trực tiếp
```promql
# Copy expression từ alert rule và test
# Ví dụ alert: FilebeatEventsDropped
rate(filebeat_events_dropped_total[5m]) > 100
```

**Step 3:** Kiểm tra `for` duration
- Alert có `for: 10m` → cần condition true trong 10 phút
- State = "Pending" → đang đếm thời gian
- State = "Firing" → đã fire

### ❌ Problem: Metric có data nhưng giá trị không đúng

**Ví dụ:** Memory usage query return giá trị > 100%

**Nguyên nhân:** 
- Unit conversion sai
- Sử dụng sai metric

**Cách debug:**

**Step 1:** Xem raw metric values
```promql
# Xem memory usage (bytes)
container_memory_usage_bytes{container="filebeat"}

# Xem memory limit (bytes)
container_spec_memory_limit_bytes{container="filebeat"}
```

**Step 2:** Test từng phần của formula
```promql
# Phần 1
container_memory_usage_bytes{container="filebeat"}

# Phần 2
container_spec_memory_limit_bytes{container="filebeat"}

# Combined (tỷ lệ)
container_memory_usage_bytes{container="filebeat"} / container_spec_memory_limit_bytes{container="filebeat"}

# Phần trăm
container_memory_usage_bytes{container="filebeat"} / container_spec_memory_limit_bytes{container="filebeat"} * 100
```

### ❌ Problem: Kafka consumer lag metric không có

**Giải pháp alternatives:**

**Option 1:** Check nếu đang dùng kafka-exporter
```promql
# Search trong metrics explorer
kafka_consumer
kafka_lag
```

**Option 2:** Deploy kafka-lag-exporter
```bash
# Sử dụng kafka-lag-exporter
# https://github.com/seglo/kafka-lag-exporter
```

**Option 3:** Sử dụng Burrow metrics
```promql
kafka_burrow_partition_lag
```

**Option 4:** Monitor indirect signs
```promql
# Queue depth increasing = consumer lag
increase(kafka_log_log_size[1h])

# Consumer throughput
rate(kafka_consumer_fetch_manager_records_consumed_total[5m])
```

---

## 16. Tips & Best Practices khi test trên GUI

### 💡 Tip 1: Sử dụng "Add Panel" để compare metrics

**Trong Graph tab:**
- Click "Add Query"
- Nhập nhiều queries để so sánh
- Ví dụ:
  ```promql
  Query 1: rate(logstash_pipeline_events_in_total[5m])
  Query 2: rate(logstash_pipeline_events_out_total[5m])
  ```
- Giúp dễ thấy nếu input/output không match

### 💡 Tip 2: Sử dụng "Instant" query cho current value

**Toggle giữa:**
- **Graph**: Xem time series
- **Table**: Xem giá trị hiện tại của tất cả series

**Hữu ích khi:**
- Check current status (up/down)
- Xem giá trị chính xác của metrics
- So sánh giữa nhiều instances

### 💡 Tip 3: Save useful queries

**Sử dụng browser bookmarks:**
```
http://localhost:9090/graph?g0.expr=up%7Bjob%3D%22filebeat%22%7D&g0.tab=0
```
Hoặc copy query vào notepad để reuse

### 💡 Tip 4: Adjust time range phù hợp

**Recommendations:**
- **Last 5m**: Quick check hiện tại
- **Last 1h**: Xem trends gần đây
- **Last 24h**: Troubleshoot incidents
- **Last 7d**: Capacity planning

### 💡 Tip 5: Sử dụng "Enable query history"

- Click vào icon clock (góc trên bên phải query box)
- Xem lại các queries đã chạy
- Không cần gõ lại

### 💡 Tip 6: Format queries cho dễ đọc

**Bad:**
```promql
rate(container_cpu_usage_seconds_total{container="filebeat",namespace="logging"}[5m])
```

**Good:** (có thể xuống dòng trong Prometheus)
```promql
rate(
  container_cpu_usage_seconds_total{
    container="filebeat",
    namespace="logging"
  }[5m]
)
```

### 13.1 Bash script để test metrics

```bash
#!/bin/bash

PROMETHEUS_URL="http://prometheus.monitoring.svc.cluster.local:9090"

echo "=== Testing Metrics Availability ==="
echo ""

# Function to test metric
test_metric() {
    local metric=$1
    local description=$2
    
    echo -n "Testing $description... "
    result=$(curl -s "${PROMETHEUS_URL}/api/v1/query?query=${metric}" | jq -r '.data.result | length')
    
    if [ "$result" -gt 0 ]; then
        echo "✓ OK ($result series found)"
    else
        echo "✗ FAIL (no data)"
    fi
}

# Filebeat metrics
echo "--- Filebeat Metrics ---"
test_metric "up{job=\"filebeat\"}" "Filebeat up status"
test_metric "filebeat_events_dropped_total" "Filebeat events dropped"
test_metric "filebeat_libbeat_output_events_failed_total" "Filebeat output failures"
test_metric "container_memory_usage_bytes{container=\"filebeat\"}" "Filebeat memory usage"

# Kafka metrics
echo ""
echo "--- Kafka Metrics ---"
test_metric "kafka_server_replicamanager_leadercount" "Kafka leader count"
test_metric "kafka_server_replicamanager_underreplicatedpartitions" "Kafka under-replicated partitions"
test_metric "kafka_controller_kafkacontroller_offlinepartitionscount" "Kafka offline partitions"
test_metric "kafka_consumergroup_lag" "Kafka consumer lag"

# Logstash metrics
echo ""
echo "--- Logstash Metrics ---"
test_metric "up{job=\"logstash\"}" "Logstash up status"
test_metric "logstash_pipeline_events_in_total" "Logstash events in"
test_metric "logstash_pipeline_events_out_total" "Logstash events out"
test_metric "logstash_pipeline_queue_events" "Logstash queue events"

# OpenSearch metrics
echo ""
echo "--- OpenSearch Metrics ---"
test_metric "opensearch_cluster_health_status" "OpenSearch cluster health"
test_metric "up{job=\"opensearch\"}" "OpenSearch node up"
test_metric "opensearch_jvm_mem_heap_used_percent" "OpenSearch JVM heap"
test_metric "opensearch_filesystem_data_available_bytes" "OpenSearch disk space"

# OpenSearch Dashboard metrics
echo ""
echo "--- OpenSearch Dashboard Metrics ---"
test_metric "up{job=\"opensearch-dashboards\"}" "Dashboard up status"

# AKHQ metrics
echo ""
echo "--- AKHQ Metrics ---"
test_metric "up{job=\"akhq\"}" "AKHQ up status"

# Kubernetes metrics
echo ""
echo "--- Kubernetes Metrics ---"
test_metric "kube_pod_container_status_restarts_total" "Pod restart count"
test_metric "kube_pod_status_phase" "Pod status phase"
test_metric "kubelet_volume_stats_used_bytes" "Volume usage"

echo ""
echo "=== Test Complete ==="
```

### 13.2 Python script để kiểm tra chi tiết

```python
#!/usr/bin/env python3
import requests
import json
from tabulate import tabulate

PROMETHEUS_URL = "http://prometheus.monitoring.svc.cluster.local:9090"

def query_prometheus(query):
    """Query Prometheus and return results"""
    try:
        response = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={'query': query},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        return data.get('data', {}).get('result', [])
    except Exception as e:
        return None

def check_metrics():
    """Check all metrics availability"""
    
    metrics_to_check = {
        "Filebeat": [
            ("up{job=\"filebeat\"}", "Up status"),
            ("filebeat_events_dropped_total", "Events dropped"),
            ("filebeat_libbeat_output_events_failed_total", "Output failures"),
        ],
        "Kafka": [
            ("kafka_server_replicamanager_leadercount", "Leader count"),
            ("kafka_server_replicamanager_underreplicatedpartitions", "Under-replicated partitions"),
            ("kafka_consumergroup_lag", "Consumer lag"),
        ],
        "Logstash": [
            ("up{job=\"logstash\"}", "Up status"),
            ("logstash_pipeline_events_in_total", "Events in"),
            ("logstash_pipeline_events_out_total", "Events out"),
        ],
        "OpenSearch": [
            ("opensearch_cluster_health_status", "Cluster health"),
            ("opensearch_jvm_mem_heap_used_percent", "JVM heap usage"),
            ("opensearch_filesystem_data_available_bytes", "Disk available"),
        ],
        "Kubernetes": [
            ("kube_pod_container_status_restarts_total", "Pod restarts"),
            ("kube_pod_status_phase", "Pod phases"),
        ]
    }
    
    results = []
    
    for component, metrics in metrics_to_check.items():
        for query, description in metrics:
            result = query_prometheus(query)
            
            if result is None:
                status = "❌ ERROR"
                count = 0
                sample_value = "N/A"
            elif len(result) > 0:
                status = "✅ OK"
                count = len(result)
                sample_value = result[0].get('value', [None, 'N/A'])[1]
            else:
                status = "⚠️  NO DATA"
                count = 0
                sample_value = "N/A"
            
            results.append([
                component,
                description,
                query,
                status,
                count,
                sample_value
            ])
    
    # Print results as table
    headers = ["Component", "Description", "Query", "Status", "Series", "Sample Value"]
    print(tabulate(results, headers=headers, tablefmt="grid"))
    
    # Summary
    total = len(results)
    ok = sum(1 for r in results if r[3] == "✅ OK")
    print(f"\n{'='*80}")
    print(f"Summary: {ok}/{total} metrics available ({ok*100//total}%)")
    print(f"{'='*80}")

if __name__ == "__main__":
    print("Checking Prometheus Metrics Availability...")
    print("=" * 80)
    check_metrics()
```

### 13.3 Kubectl commands để kiểm tra

```bash
# 1. Port-forward Prometheus
kubectl port-forward -n monitoring svc/prometheus 9090:9090 &

# 2. Kiểm tra targets đang được scrape
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health, lastError: .lastError}'

# 3. Kiểm tra tất cả metrics có sẵn
curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]' | sort

# 4. Kiểm tra metrics của một component cụ thể
curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]' | grep filebeat
curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]' | grep kafka
curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]' | grep logstash
curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]' | grep opensearch

# 5. Query một metric cụ thể
curl -s 'http://localhost:9090/api/v1/query?query=up{job="filebeat"}' | jq .

# 6. Kiểm tra ServiceMonitor đang hoạt động
kubectl get servicemonitor -n logging
kubectl describe servicemonitor filebeat -n logging
```

---

## 14. Troubleshooting Guide

### 14.1 Nếu không tìm thấy metrics

#### Filebeat metrics missing
```bash
# Kiểm tra Filebeat có expose metrics không
kubectl exec -it filebeat-xxx -n logging -- curl localhost:5066/stats

# Kiểm tra ServiceMonitor
kubectl get servicemonitor filebeat -n logging -o yaml

# Kiểm tra Service có đúng label selector không
kubectl get svc -n logging -l app=filebeat --show-labels

# Kiểm tra Prometheus targets
kubectl port-forward -n monitoring svc/prometheus 9090:9090
# Truy cập http://localhost:9090/targets
```

#### Kafka metrics missing
```bash
# Nếu dùng JMX Exporter, kiểm tra JMX port
kubectl exec -it kafka-0 -n logging -- netstat -tlnp | grep 9308

# Nếu dùng kafka-exporter
kubectl get pods -n logging -l app=kafka-exporter
kubectl logs -n logging kafka-exporter-xxx

# Kiểm tra Kafka metrics endpoint
kubectl exec -it kafka-0 -n logging -- curl localhost:9308/metrics
```

#### Logstash metrics missing
```bash
# Kiểm tra Logstash monitoring API
kubectl exec -it logstash-xxx -n logging -- curl localhost:9600/_node/stats

# Kiểm tra config
kubectl exec -it logstash-xxx -n logging -- cat /usr/share/logstash/config/logstash.yml | grep monitoring
```

#### OpenSearch metrics missing
```bash
# Kiểm tra OpenSearch metrics endpoint
kubectl exec -it opensearch-0 -n logging -- curl localhost:9200/_prometheus/metrics

# Nếu không có, cần cài prometheus exporter plugin
kubectl exec -it opensearch-0 -n logging -- bin/opensearch-plugin list
# Nên thấy: prometheus-exporter
```

### 14.2 Alternative metrics nếu thiếu

#### Nếu không có Filebeat-specific metrics
```promql
# Sử dụng container metrics thay thế
rate(container_cpu_usage_seconds_total{container="filebeat"}[5m])
container_memory_working_set_bytes{container="filebeat"}

# Kiểm tra pod restarts (indirect indicator)
rate(kube_pod_container_status_restarts_total{container="filebeat"}[1h])
```

#### Nếu không có Kafka consumer lag metrics
```bash
# Dùng kafka-consumer-groups command
kubectl exec -it kafka-0 -n logging -- kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 \
  --describe --group logstash

# Hoặc deploy kafka-lag-exporter
# https://github.com/seglo/kafka-lag-exporter
```

#### Nếu không có OpenSearch-specific metrics
```promql
# Sử dụng HTTP probe
probe_success{job="opensearch-http"}

# Container metrics
container_memory_usage_bytes{container="opensearch"}
rate(container_cpu_usage_seconds_total{container="opensearch"}[5m])
```

---

## Tài liệu tham khảo
- Prometheus Alerting Best Practices: https://prometheus.io/docs/practices/alerting/
- Kafka Monitoring: https://kafka.apache.org/documentation/#monitoring
- OpenSearch Monitoring: https://opensearch.org/docs/latest/monitoring-plugins/
- Filebeat Monitoring: https://www.elastic.co/guide/en/beats/filebeat/current/monitoring.html
- Prometheus Query API: https://prometheus.io/docs/prometheus/latest/querying/api/