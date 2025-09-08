# Triển khai Kafka Cluster, Filebeat, Logstash với Helm

## Tổng quan kiến trúc

```
[Applications] → [Filebeat] → [Kafka Cluster] → [Logstash] → [Elasticsearch]
```

- **Filebeat**: Thu thập logs từ các ứng dụng
- **Kafka**: Message broker với xác thực SASL/PLAIN
- **Logstash**: Xử lý và chuyển đổi logs trước khi gửi đến Elasticsearch

## 1. Chuẩn bị môi trường

### Thêm Helm repositories

```bash
# Thêm Bitnami repository cho Kafka
helm repo add bitnami https://charts.bitnami.com/bitnami

# Thêm Elastic repository cho Filebeat và Logstash
helm repo add elastic https://helm.elastic.co

# Cập nhật repositories
helm repo update
```

### Tạo namespace

```bash
kubectl create namespace logging
```

## 2. Triển khai Kafka Cluster với xác thực

### Tạo Kafka values file

```yaml
# kafka-values.yaml
auth:
  clientProtocol: sasl
  interBrokerProtocol: sasl
  sasl:
    mechanisms: plain
    interBrokerMechanism: plain
  jaas:
    clientUsers:
      - "logstash"
      - "filebeat"
      - "admin"
    clientPasswords:
      - "logstash-password"
      - "filebeat-password"
      - "admin-password"
    interBrokerUser: "admin"
    interBrokerPassword: "admin-password"

listeners:
  client:
    protocol: SASL_PLAINTEXT
  interbroker:
    protocol: SASL_PLAINTEXT

kraft:
  enabled: true

controller:
  replicaCount: 3

broker:
  replicaCount: 3
  persistence:
    enabled: true
    size: 10Gi

zookeeper:
  enabled: false

externalAccess:
  enabled: false

service:
  type: ClusterIP
  ports:
    client: 9092

metrics:
  kafka:
    enabled: true
  jmx:
    enabled: true

resources:
  limits:
    cpu: 1000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 1Gi
```

### Triển khai Kafka

```bash
helm install kafka bitnami/kafka \
  --namespace logging \
  --values kafka-values.yaml \
  --version 26.4.2
```

## 3. Triển khai Logstash với xác thực Kafka

### Tạo Logstash configuration

```yaml
# logstash-values.yaml
replicas: 2

logstashConfig:
  logstash.yml: |
    http.host: "0.0.0.0"
    xpack.monitoring.elasticsearch.hosts: [ "http://elasticsearch:9200" ]

logstashPipeline:
  logstash.conf: |
    input {
      kafka {
        bootstrap_servers => "kafka:9092"
        topics => ["filebeat-logs"]
        group_id => "logstash-group"
        security_protocol => "SASL_PLAINTEXT"
        sasl_mechanism => "PLAIN"
        sasl_jaas_config => "org.apache.kafka.common.security.plain.PlainLoginModule required username='logstash' password='logstash-password';"
        codec => "json"
        consumer_threads => 2
      }
    }
    
    filter {
      # Parse timestamp
      date {
        match => [ "@timestamp", "ISO8601" ]
      }
      
      # Add hostname field
      if [host] {
        mutate {
          add_field => { "hostname" => "%{[host][name]}" }
        }
      }
      
      # Parse log level
      grok {
        match => { "message" => "%{LOGLEVEL:log_level}" }
        tag_on_failure => ["_grokparsefailure_loglevel"]
      }
      
      # Remove unnecessary fields
      mutate {
        remove_field => [ "[host]", "[agent]", "[ecs]", "[log][file]" ]
      }
    }
    
    output {
      elasticsearch {
        hosts => ["http://elasticsearch:9200"]
        index => "logstash-logs-%{+YYYY.MM.dd}"
      }
      
      # Debug output
      stdout {
        codec => rubydebug
      }
    }

service:
  type: ClusterIP
  ports:
    - name: beats
      port: 5044
      protocol: TCP
      targetPort: 5044

resources:
  requests:
    cpu: "500m"
    memory: "1Gi"
  limits:
    cpu: "1000m"
    memory: "2Gi"

persistence:
  enabled: false

volumeClaimTemplate:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 5Gi
```

### Triển khai Logstash

```bash
helm install logstash elastic/logstash \
  --namespace logging \
  --values logstash-values.yaml \
  --version 8.5.1
```

## 4. Triển khai Filebeat

### Tạo Filebeat configuration

```yaml
# filebeat-values.yaml
daemonset:
  enabled: true

deployment:
  enabled: false

filebeatConfig:
  filebeat.yml: |
    filebeat.inputs:
    - type: container
      paths:
        - /var/log/containers/*.log
      processors:
      - add_kubernetes_metadata:
          host: ${NODE_NAME}
          matchers:
          - logs_path:
              logs_path: "/var/log/containers/"
    
    - type: log
      paths:
        - /var/log/syslog
        - /var/log/auth.log
      fields:
        log_type: system
      fields_under_root: true
    
    processors:
    - add_host_metadata:
        when.not.contains.tags: forwarded
    
    output.kafka:
      hosts: ["kafka:9092"]
      topic: "filebeat-logs"
      partition.round_robin:
        reachable_only: false
      required_acks: 1
      compression: gzip
      max_message_bytes: 1000000
      sasl.mechanism: PLAIN
      sasl.username: "filebeat"
      sasl.password: "filebeat-password"
      security.protocol: "SASL_PLAINTEXT"
    
    logging.level: info
    logging.to_files: true
    logging.files:
      path: /usr/share/filebeat/logs
      name: filebeat
      keepfiles: 7
      permissions: 0644

extraVolumes:
  - name: varlog
    hostPath:
      path: /var/log
  - name: varlibdockercontainers
    hostPath:
      path: /var/lib/docker/containers

extraVolumeMounts:
  - name: varlog
    mountPath: /var/log
    readOnly: true
  - name: varlibdockercontainers
    mountPath: /var/lib/docker/containers
    readOnly: true

resources:
  requests:
    cpu: "100m"
    memory: "100Mi"
  limits:
    cpu: "200m"
    memory: "200Mi"

serviceAccount:
  create: true
  name: filebeat

podSecurityContext:
  runAsUser: 0
  privileged: true

tolerations:
  - effect: NoSchedule
    operator: Exists

nodeSelector: {}
```

### Triển khai Filebeat

```bash
helm install filebeat elastic/filebeat \
  --namespace logging \
  --values filebeat-values.yaml \
  --version 8.5.1
```

## 5. Commands kiểm tra hệ thống

### Kiểm tra trạng thái pods

```bash
# Kiểm tra tất cả pods trong namespace logging
kubectl get pods -n logging

# Kiểm tra logs của các pods
kubectl logs -n logging deployment/logstash-logstash -f
kubectl logs -n logging daemonset/filebeat-filebeat -f
kubectl logs -n logging statefulset/kafka -f
```

### Kiểm tra Kafka với xác thực

```bash
# Tạo pod client để test Kafka
kubectl run kafka-client --restart='Never' --image docker.io/bitnami/kafka:3.6.0-debian-11-r0 --namespace logging --command -- sleep infinity

# Exec vào pod client
kubectl exec --tty -i kafka-client --namespace logging -- bash

# Tạo file cấu hình SASL
cat > /tmp/client.properties << EOF
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="admin" password="admin-password";
EOF
```

### Test Kafka topics và messages

```bash
# Liệt kê topics (trong kafka-client pod)
kafka-topics.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties --list

# Tạo topic test
kafka-topics.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties --create --topic test-topic --partitions 3 --replication-factor 3

# Mô tả topic filebeat-logs
kafka-topics.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties --describe --topic filebeat-logs

# Gửi message test
echo "test message" | kafka-console-producer.sh --bootstrap-server kafka:9092 --producer.config /tmp/client.properties --topic test-topic

# Đọc messages từ topic
kafka-console-consumer.sh --bootstrap-server kafka:9092 --consumer.config /tmp/client.properties --topic filebeat-logs --from-beginning --max-messages 10
```

### Kiểm tra consumer groups

```bash
# Liệt kê consumer groups
kafka-consumer-groups.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties --list

# Kiểm tra offset của logstash consumer group
kafka-consumer-groups.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties --describe --group logstash-group
```

### Monitor Kafka cluster

```bash
# Kiểm tra cluster metadata
kafka-metadata.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties

# Kiểm tra broker configs
kafka-configs.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties --entity-type brokers --describe --entity-name 0
```

## 6. Kiểm tra kết nối pipeline

### Test end-to-end pipeline

```bash
# Tạo log test file trên node
kubectl exec -n logging daemonset/filebeat-filebeat -- bash -c 'echo "$(date) [INFO] Test log message from filebeat" >> /var/log/test.log'

# Kiểm tra message trong Kafka topic
kafka-console-consumer.sh --bootstrap-server kafka:9092 --consumer.config /tmp/client.properties --topic filebeat-logs --from-beginning --max-messages 1

# Kiểm tra logs Logstash để xác nhận xử lý
kubectl logs -n logging deployment/logstash-logstash --tail=50
```

### Kiểm tra performance

```bash
# Kiểm tra resource usage của pods
kubectl top pods -n logging

# Kiểm tra Kafka topic statistics
kafka-run-class.sh kafka.tools.GetOffsetShell --bootstrap-server kafka:9092 --command-config /tmp/client.properties --topic filebeat-logs

# Test producer performance
kafka-producer-perf-test.sh --topic test-topic --num-records 1000 --record-size 1024 --throughput 100 --producer-props bootstrap.servers=kafka:9092 --producer.config /tmp/client.properties
```

## 7. Troubleshooting Commands

### Debug Kafka authentication

```bash
# Kiểm tra SASL config
kubectl exec -n logging kafka-0 -- cat /opt/bitnami/kafka/config/kafka_jaas.conf

# Test kết nối từ pod khác
kubectl run test-kafka-connection --rm -i --tty --image=bitnami/kafka:3.6.0 --restart=Never -- kafka-topics.sh --bootstrap-server kafka:9092 --command-config /tmp/client.properties --list
```

### Debug Logstash

```bash
# Kiểm tra Logstash pipeline config
kubectl exec -n logging deployment/logstash-logstash -- cat /usr/share/logstash/pipeline/logstash.conf

# Test config syntax
kubectl exec -n logging deployment/logstash-logstash -- logstash --config.test_and_exit --path.config /usr/share/logstash/pipeline/
```

### Debug Filebeat

```bash
# Kiểm tra Filebeat config
kubectl exec -n logging daemonset/filebeat-filebeat -- cat /usr/share/filebeat/filebeat.yml

# Test output connectivity
kubectl exec -n logging daemonset/filebeat-filebeat -- filebeat test output
```

## 8. Cleanup Commands

```bash
# Xóa tất cả deployments
helm uninstall filebeat -n logging
helm uninstall logstash -n logging  
helm uninstall kafka -n logging

# Xóa namespace
kubectl delete namespace logging

# Xóa kafka client pod
kubectl delete pod kafka-client -n logging
```

## Lưu ý quan trọng

1. **Bảo mật**: Passwords trong file values nên được lưu trữ an toàn và sử dụng Kubernetes Secrets trong production
2. **Persistence**: Kafka sử dụng persistent volumes, cần đảm bảo storage class phù hợp
3. **Resources**: Điều chỉnh CPU/Memory limits theo nhu cầu thực tế
4. **Network**: Đảm bảo các pods có thể kết nối với nhau qua service names
5. **Monitoring**: Thêm Prometheus metrics để theo dõi performance