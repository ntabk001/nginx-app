# Kubernetes Logging Stack - Troubleshooting Guide

Hướng dẫn troubleshooting chi tiết cho logging stack gồm: Filebeat, Logstash, Kafka, OpenSearch, OpenSearch Dashboards, và AKHQ

---

## 1. FILEBEAT

### 1.1. Pod CrashLoopBackOff

**Triệu chứng:**
- Pod Filebeat liên tục restart
- Status hiển thị `CrashLoopBackOff` hoặc `Error`

**Cách kiểm tra:**

```bash
# Kiểm tra status của pods
kubectl get pods -n logging | grep filebeat

# Xem logs của pod
kubectl logs -n logging <filebeat-pod-name>

# Xem logs của lần chạy trước (nếu pod đã restart)
kubectl logs -n logging <filebeat-pod-name> --previous

# Describe pod để xem events
kubectl describe pod -n logging <filebeat-pod-name>
```

**Nguyên nhân thường gặp:**
- Config file sai cú pháp YAML
- Thiếu quyền truy cập vào logs trên node
- Thiếu resources (CPU/Memory)
- Output (Logstash/Kafka) không available

**Cách khắc phục:**

```bash
# Kiểm tra config
kubectl get configmap -n logging filebeat-config -o yaml

# Test config syntax (exec vào pod nếu đang running)
kubectl exec -it -n logging <filebeat-pod-name> -- filebeat test config

# Kiểm tra resources
kubectl top pod -n logging <filebeat-pod-name>

# Tăng resources nếu cần
kubectl edit deployment -n logging filebeat
# Hoặc
kubectl edit daemonset -n logging filebeat
```

---

### 1.2. Không kết nối được với Logstash/Kafka

**Triệu chứng:**
- Logs không được gửi đến Logstash hoặc Kafka
- Filebeat logs hiển thị connection errors

**Cách kiểm tra:**

```bash
# Xem logs Filebeat để tìm connection errors
kubectl logs -n logging <filebeat-pod-name> | grep -i "error\|connection\|refused"

# Kiểm tra network connectivity
kubectl exec -it -n logging <filebeat-pod-name> -- sh
# Trong pod:
ping logstash-service
telnet logstash-service 5044
nc -zv logstash-service 5044

# Kiểm tra Logstash service
kubectl get svc -n logging | grep logstash
kubectl get endpoints -n logging logstash-service

# Kiểm tra Kafka service
kubectl get svc -n logging | grep kafka
kubectl get endpoints -n logging kafka-service
```

**Cách khắc phục:**

```bash
# Kiểm tra output configuration trong ConfigMap
kubectl get configmap -n logging filebeat-config -o yaml

# Sửa output configuration
kubectl edit configmap -n logging filebeat-config

# Restart Filebeat pods
kubectl rollout restart daemonset -n logging filebeat
```

---

### 1.3. Logs không được thu thập

**Triệu chứng:**
- Filebeat chạy bình thường nhưng không thu thập logs
- Không có data trong OpenSearch

**Cách kiểm tra:**

```bash
# Kiểm tra Filebeat đang scan paths nào
kubectl logs -n logging <filebeat-pod-name> | grep -i "prospector\|input"

# Kiểm tra volume mounts
kubectl describe pod -n logging <filebeat-pod-name> | grep -A 10 "Mounts:"

# Exec vào pod và kiểm tra logs path
kubectl exec -it -n logging <filebeat-pod-name> -- sh
ls -la /var/log/containers/
ls -la /var/lib/docker/containers/

# Test output connectivity
kubectl exec -it -n logging <filebeat-pod-name> -- filebeat test output
```

**Cách khắc phục:**

```bash
# Kiểm tra volume configuration
kubectl get daemonset -n logging filebeat -o yaml | grep -A 20 "volumes:"

# Kiểm tra autodiscover configuration
kubectl get configmap -n logging filebeat-config -o yaml

# Enable debug logging
kubectl edit configmap -n logging filebeat-config
# Thêm: logging.level: debug

# Restart pods
kubectl rollout restart daemonset -n logging filebeat
```

---

## 2. LOGSTASH

### 2.1. Service bị down

**Triệu chứng:**
- Pod status không phải `Running`
- Service không response
- Filebeat không connect được

**Cách kiểm tra:**

```bash
# Kiểm tra pod status
kubectl get pods -n logging | grep logstash

# Xem logs
kubectl logs -n logging <logstash-pod-name>
kubectl logs -n logging <logstash-pod-name> --previous

# Describe pod
kubectl describe pod -n logging <logstash-pod-name>

# Kiểm tra events
kubectl get events -n logging --sort-by='.lastTimestamp' | grep logstash
```

**Nguyên nhân thường gặp:**
- JVM heap memory không đủ
- Pipeline configuration lỗi
- Không connect được Kafka/OpenSearch
- Liveness/Readiness probe fail

**Cách khắc phục:**

```bash
# Kiểm tra JVM settings
kubectl get deployment -n logging logstash -o yaml | grep -i "LS_JAVA_OPTS\|JAVA_OPTS"

# Test pipeline config
kubectl exec -it -n logging <logstash-pod-name> -- sh
/usr/share/logstash/bin/logstash --config.test_and_exit -f /usr/share/logstash/pipeline/logstash.conf

# Kiểm tra và tăng resources
kubectl edit deployment -n logging logstash

# Kiểm tra probe settings
kubectl get deployment -n logging logstash -o yaml | grep -A 10 "livenessProbe\|readinessProbe"
```

---

### 2.2. Memory/CPU cao

**Triệu chứng:**
- Pod bị OOMKilled
- Xử lý chậm, pipeline bị lag
- CPU/Memory usage cao

**Cách kiểm tra:**

```bash
# Kiểm tra resource usage
kubectl top pod -n logging | grep logstash

# Xem pod events để tìm OOMKilled
kubectl describe pod -n logging <logstash-pod-name> | grep -i "oom\|killed"

# Kiểm tra metrics qua API
kubectl exec -it -n logging <logstash-pod-name> -- curl -s "localhost:9600/_node/stats/jvm"

# Xem heap usage
kubectl exec -it -n logging <logstash-pod-name> -- curl -s "localhost:9600/_node/stats/jvm" | jq '.jvm.mem'
```

**Cách khắc phục:**

```bash
# Tăng JVM heap
kubectl edit deployment -n logging logstash
# Thêm env: LS_JAVA_OPTS="-Xmx2g -Xms2g"

# Tăng resources limit
kubectl edit deployment -n logging logstash
# Tăng resources.limits.memory và resources.requests.memory

# Scale horizontal
kubectl scale deployment -n logging logstash --replicas=3

# Optimize pipeline
kubectl edit configmap -n logging logstash-pipeline
# Giảm batch_size, workers
```

---

### 2.3. Pipeline bị tắc nghẽn

**Triệu chứng:**
- Events không được xử lý
- Consumer lag tăng cao (nếu dùng Kafka)
- Throughput giảm

**Cách kiểm tra:**

```bash
# Kiểm tra pipeline stats
kubectl exec -it -n logging <logstash-pod-name> -- curl -s "localhost:9600/_node/stats/pipelines"

# Xem queue depth
kubectl exec -it -n logging <logstash-pod-name> -- curl -s "localhost:9600/_node/stats/pipelines" | jq '.pipelines.main.queue'

# Kiểm tra output stats
kubectl exec -it -n logging <logstash-pod-name> -- curl -s "localhost:9600/_node/stats/pipelines" | jq '.pipelines.main.plugins.outputs'

# Xem logs để tìm errors
kubectl logs -n logging <logstash-pod-name> | grep -i "error\|exception\|timeout"
```

**Cách khắc phục:**

```bash
# Tăng batch size và workers
kubectl edit configmap -n logging logstash-pipeline
# pipeline.batch.size: 500
# pipeline.workers: 4

# Enable persistent queue
kubectl edit configmap -n logging logstash-pipeline
# queue.type: persisted
# queue.max_bytes: 1gb

# Optimize output
# Tăng bulk size cho OpenSearch output
# Tăng flush_interval

# Scale replicas
kubectl scale deployment -n logging logstash --replicas=3
```

---

## 3. KAFKA

### 3.1. Broker không healthy

**Triệu chứng:**
- Broker pod không ở trạng thái Running
- ISR (In-Sync Replicas) giảm
- Under-replicated partitions

**Cách kiểm tra:**

```bash
# Kiểm tra pod status
kubectl get pods -n logging | grep kafka

# Xem logs
kubectl logs -n logging <kafka-pod-name>

# Kiểm tra broker health qua kafka tools
kubectl exec -it -n logging <kafka-pod-name> -- kafka-broker-api-versions --bootstrap-server localhost:9092

# List brokers
kubectl exec -it -n logging <kafka-pod-name> -- kafka-broker-api-versions --bootstrap-server kafka:9092

# Describe cluster
kubectl exec -it -n logging <kafka-pod-name> -- kafka-metadata --bootstrap-server localhost:9092 --describe
```

**Cách khắc phục:**

```bash
# Kiểm tra resources
kubectl top pod -n logging | grep kafka

# Kiểm tra persistent volume
kubectl get pv | grep kafka
kubectl get pvc -n logging | grep kafka

# Restart specific broker
kubectl delete pod -n logging <kafka-pod-name>

# Kiểm tra StatefulSet
kubectl get statefulset -n logging kafka -o yaml
```

---

### 3.2. Consumer lag cao

**Triệu chứng:**
- Độ trễ giữa producer và consumer tăng
- Messages không được xử lý kịp thời
- OpenSearch nhận data chậm

**Cách kiểm tra:**

```bash
# Kiểm tra consumer groups
kubectl exec -it -n logging <kafka-pod-name> -- kafka-consumer-groups --bootstrap-server localhost:9092 --list

# Xem lag của consumer group
kubectl exec -it -n logging <kafka-pod-name> -- kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --group logstash-consumer-group \
  --describe

# Kiểm tra topic details
kubectl exec -it -n logging <kafka-pod-name> -- kafka-topics \
  --bootstrap-server localhost:9092 \
  --describe \
  --topic logs-topic

# Xem throughput qua AKHQ
kubectl port-forward -n logging svc/akhq 8080:8080
# Truy cập: http://localhost:8080
```

**Cách khắc phục:**

```bash
# Tăng số partitions
kubectl exec -it -n logging <kafka-pod-name> -- kafka-topics \
  --bootstrap-server localhost:9092 \
  --alter \
  --topic logs-topic \
  --partitions 6

# Scale Logstash consumers
kubectl scale deployment -n logging logstash --replicas=3

# Tăng fetch size trong Logstash config
kubectl edit configmap -n logging logstash-pipeline
# consumer_threads => 4
# max_poll_records => 1000

# Restart Logstash
kubectl rollout restart deployment -n logging logstash
```

---

### 3.3. Disk đầy

**Triệu chứng:**
- Kafka không thể write messages
- Logs hiển thị disk space errors
- Producer bị block

**Cách kiểm tra:**

```bash
# Kiểm tra disk usage
kubectl exec -it -n logging <kafka-pod-name> -- df -h

# Kiểm tra logs directory
kubectl exec -it -n logging <kafka-pod-name> -- du -sh /var/lib/kafka/data/*

# Kiểm tra PVC usage
kubectl get pvc -n logging | grep kafka
kubectl describe pvc -n logging <kafka-pvc-name>

# Kiểm tra retention policy
kubectl exec -it -n logging <kafka-pod-name> -- kafka-configs \
  --bootstrap-server localhost:9092 \
  --entity-type topics \
  --entity-name logs-topic \
  --describe
```

**Cách khắc phục:**

```bash
# Giảm retention time
kubectl exec -it -n logging <kafka-pod-name> -- kafka-configs \
  --bootstrap-server localhost:9092 \
  --entity-type topics \
  --entity-name logs-topic \
  --alter \
  --add-config retention.ms=86400000  # 1 day

# Giảm retention size
kubectl exec -it -n logging <kafka-pod-name> -- kafka-configs \
  --bootstrap-server localhost:9092 \
  --entity-type topics \
  --entity-name logs-topic \
  --alter \
  --add-config retention.bytes=10737418240  # 10GB

# Tăng PVC size
kubectl edit pvc -n logging <kafka-pvc-name>
# Tăng storage size (cần StorageClass hỗ trợ expansion)

# Delete old segments manually (cẩn thận!)
kubectl exec -it -n logging <kafka-pod-name> -- sh
cd /var/lib/kafka/data/logs-topic-0/
# Xóa các .log files cũ
```

---

## 4. OPENSEARCH

### 4.1. Cluster status Yellow

**Triệu chứng:**
- Cluster health = yellow
- Một số replica shards chưa được allocated
- Có thể vẫn index và search được

**Cách kiểm tra:**

```bash
# Kiểm tra cluster health
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cluster/health?pretty"

# Kiểm tra unassigned shards
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/shards?v&h=index,shard,prirep,state,node,unassigned.reason" | grep UNASSIGNED

# Xem allocation explain
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s -XGET "http://localhost:9200/_cluster/allocation/explain?pretty"

# Kiểm tra nodes
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/nodes?v"
```

**Cách khắc phục:**

```bash
# Scale thêm nodes nếu thiếu nodes
kubectl scale statefulset -n logging opensearch --replicas=3

# Giảm replica count
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPUT "http://localhost:9200/_all/_settings" \
  -H 'Content-Type: application/json' -d'{
    "index": {
      "number_of_replicas": 1
    }
}'

# Force allocation nếu cần
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPOST "http://localhost:9200/_cluster/reroute?retry_failed=true"

# Kiểm tra disk watermark settings
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cluster/settings?pretty" | grep watermark
```

---

### 4.2. Cluster status Red

**Triệu chứng:**
- Cluster health = red
- Primary shards chưa được allocated
- Mất data, không thể query một số indices

**Cách kiểm tra:**

```bash
# Kiểm tra cluster health
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cluster/health?pretty"

# Tìm indices có vấn đề
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/indices?v&health=red"

# Kiểm tra shards
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/shards?v" | grep -E "UNASSIGNED|INITIALIZING"

# Xem lý do unassigned
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XGET "http://localhost:9200/_cluster/allocation/explain?pretty"

# Xem logs
kubectl logs -n logging <opensearch-pod-name> | grep -i "error\|exception\|failed"
```

**Cách khắc phục:**

```bash
# Restart problematic nodes
kubectl delete pod -n logging <opensearch-pod-name>

# Khôi phục từ snapshot nếu có
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPOST "http://localhost:9200/_snapshot/backup_repo/snapshot_name/_restore"

# Allocate empty primary (CẢNH BÁO: mất data!)
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPOST "http://localhost:9200/_cluster/reroute" \
  -H 'Content-Type: application/json' -d'{
    "commands": [{
      "allocate_empty_primary": {
        "index": "logs-2025.01.01",
        "shard": 0,
        "node": "opensearch-0",
        "accept_data_loss": true
      }
    }]
}'

# Delete corrupted index (solution cuối cùng)
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XDELETE "http://localhost:9200/corrupted-index"
```

---

### 4.3. Out of Memory (OOM)

**Triệu chứng:**
- Pods bị OOMKilled
- JVM heap memory đầy
- Queries bị timeout

**Cách kiểm tra:**

```bash
# Kiểm tra pod events
kubectl describe pod -n logging <opensearch-pod-name> | grep -i "oom\|killed"

# Xem resource usage
kubectl top pod -n logging | grep opensearch

# Kiểm tra JVM heap
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/nodes?v&h=name,heap.percent,heap.current,heap.max,ram.percent,ram.current,ram.max"

# Xem JVM stats
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_nodes/stats/jvm?pretty"

# Kiểm tra circuit breakers
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_nodes/stats/breaker?pretty"
```

**Cách khắc phục:**

```bash
# Tăng heap size
kubectl edit statefulset -n logging opensearch
# Sửa env: OPENSEARCH_JAVA_OPTS="-Xms2g -Xmx2g"

# Tăng pod resources
kubectl edit statefulset -n logging opensearch
# Tăng resources.limits.memory và resources.requests.memory

# Clear cache
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPOST "http://localhost:9200/_cache/clear"

# Optimize queries và mappings
# Giảm field data, sử dụng doc values

# Scale horizontal
kubectl scale statefulset -n logging opensearch --replicas=3

# Close old indices
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPOST "http://localhost:9200/old-index/_close"
```

---

### 4.4. Disk watermark exceeded

**Triệu chứng:**
- Không thể tạo new shards
- Logs hiển thị "flood stage disk watermark exceeded"
- Indices bị read-only

**Cách kiểm tra:**

```bash
# Kiểm tra disk usage
kubectl exec -it -n logging <opensearch-pod-name> -- df -h

# Xem disk usage per node
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/allocation?v"

# Kiểm tra watermark settings
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cluster/settings?pretty&include_defaults=true" | grep watermark

# Xem indices size
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/indices?v&s=store.size:desc"

# Kiểm tra read-only indices
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_all/_settings?pretty" | grep read_only
```

**Cách khắc phục:**

```bash
# Tăng PVC size
kubectl edit pvc -n logging <opensearch-pvc-name>
# Tăng storage (nếu StorageClass hỗ trợ)

# Delete old indices
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XDELETE "http://localhost:9200/logs-2024.*"

# Force merge old indices để giảm disk
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPOST "http://localhost:9200/logs-2024.12.*/_forcemerge?max_num_segments=1"

# Remove read-only block
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPUT "http://localhost:9200/_all/_settings" \
  -H 'Content-Type: application/json' -d'{
    "index.blocks.read_only_allow_delete": null
}'

# Setup ILM/ISM policy để auto delete old data
# Tạo Index State Management policy trong OpenSearch Dashboards

# Tăng watermark thresholds (tạm thời)
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPUT "http://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' -d'{
    "transient": {
      "cluster.routing.allocation.disk.watermark.low": "90%",
      "cluster.routing.allocation.disk.watermark.high": "95%",
      "cluster.routing.allocation.disk.watermark.flood_stage": "97%"
    }
}'
```

---

### 4.5. Shard allocation issues

**Triệu chứng:**
- Shards không được phân bổ đều
- Một node có quá nhiều shards
- Performance không đồng đều

**Cách kiểm tra:**

```bash
# Xem distribution của shards
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/shards?v&s=node"

# Count shards per node
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/shards" | awk '{print $8}' | sort | uniq -c

# Kiểm tra allocation settings
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cluster/settings?pretty&include_defaults=true" | grep allocation

# Xem nodes attributes
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_cat/nodeattrs?v"
```

**Cách khắc phục:**

```bash
# Enable shard rebalancing
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPUT "http://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' -d'{
    "transient": {
      "cluster.routing.rebalance.enable": "all"
    }
}'

# Manual reroute specific shard
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPOST "http://localhost:9200/_cluster/reroute" \
  -H 'Content-Type: application/json' -d'{
    "commands": [{
      "move": {
        "index": "logs-2025.01.01",
        "shard": 0,
        "from_node": "opensearch-0",
        "to_node": "opensearch-1"
      }
    }]
}'

# Adjust allocation awareness
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPUT "http://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' -d'{
    "persistent": {
      "cluster.routing.allocation.awareness.attributes": "zone",
      "cluster.routing.allocation.balance.shard": "0.45",
      "cluster.routing.allocation.balance.index": "0.55"
    }
}'
```

---

## 5. OPENSEARCH DASHBOARDS

### 5.1. Không kết nối được OpenSearch backend

**Triệu chứng:**
- Dashboard hiển thị "OpenSearch Dashboards server is not ready yet"
- Connection refused errors
- 502 Bad Gateway

**Cách kiểm tra:**

```bash
# Kiểm tra pod status
kubectl get pods -n logging | grep opensearch-dashboards

# Xem logs
kubectl logs -n logging <dashboards-pod-name>

# Test connectivity từ dashboard pod
kubectl exec -it -n logging <dashboards-pod-name> -- sh
curl -v http://opensearch:9200
curl -v http://opensearch:9200/_cluster/health

# Kiểm tra service
kubectl get svc -n logging opensearch
kubectl get endpoints -n logging opensearch

# Kiểm tra config
kubectl get configmap -n logging opensearch-dashboards-config -o yaml
```

**Cách khắc phục:**

```bash
# Kiểm tra opensearch.hosts trong config
kubectl edit configmap -n logging opensearch-dashboards-config

# Restart dashboards
kubectl rollout restart deployment -n logging opensearch-dashboards

# Kiểm tra network policies
kubectl get networkpolicies -n logging

# Test DNS resolution
kubectl exec -it -n logging <dashboards-pod-name> -- nslookup opensearch
```

---

### 5.2. Timeout issues

**Triệu chứng:**
- Queries bị timeout
- Dashboard load chậm
- "Request Timeout" errors

**Cách kiểm tra:**

```bash
# Xem logs
kubectl logs -n logging <dashboards-pod-name> | grep -i timeout

# Kiểm tra timeout settings
kubectl get configmap -n logging opensearch-dashboards-config -o yaml | grep timeout

# Test query performance
kubectl exec -it -n logging <opensearch-pod-name> -- curl -s "http://localhost:9200/_search?pretty" \
  -H 'Content-Type: application/json' -d'{
    "query": {"match_all": {}},
    "size": 10
}'

# Kiểm tra resource usage
kubectl top pod -n logging | grep opensearch
```

**Cách khắc phục:**

```bash
# Tăng timeout trong config
kubectl edit configmap -n logging opensearch-dashboards-config
# opensearch.requestTimeout: 60000
# opensearch.shardTimeout: 30000

# Restart dashboards
kubectl rollout restart deployment -n logging opensearch-dashboards

# Optimize OpenSearch performance
# - Add more nodes
# - Increase resources
# - Optimize indices

# Tăng resources cho dashboards
kubectl edit deployment -n logging opensearch-dashboards
```

---

### 5.3. Authentication issues

**Triệu chứng:**
- Không login được
- "Authentication Exception" errors
- Session expired liên tục

**Cách kiểm tra:**

```bash
# Xem logs
kubectl logs -n logging <dashboards-pod-name> | grep -i "auth\|login\|session"

# Kiểm tra security config
kubectl get configmap -n logging opensearch-dashboards-config -o yaml | grep -i "security\|auth"

# Test authentication
curl -u admin:password http://localhost:5601/api/status

# Kiểm tra OpenSearch security
kubectl exec -it -n logging <opensearch-pod-name> -- curl -u admin:password "http://localhost:9200/_plugins/_security/api/account"
```

**Cách khắc phục:**

```bash
# Reset admin password trong OpenSearch
kubectl exec -it -n logging <opensearch-pod-name> -- sh
cd /usr/share/opensearch/plugins/opensearch-security/tools/
./hash.sh -p newpassword

# Update internal users
kubectl exec -it -n logging <opensearch-pod-name> -- curl -XPUT "http://localhost:9200/_plugins/_security/api/internalusers/admin" \
  -H 'Content-Type: application/json' -d'{
    "password": "newpassword"
}'

# Update dashboards config
kubectl edit configmap -n logging opensearch-dashboards-config
# opensearch.username: "admin"
# opensearch.password: "newpassword"

# Restart services
kubectl rollout restart deployment -n logging opensearch-dashboards
```

---

## 6. AKHQ (Kafka UI)

### 6.1. Không kết nối được Kafka

**Triệu chứng:**
- AKHQ không hiển thị topics
- "Unable to connect to Kafka" error
- Empty dashboard

**Cách kiểm tra:**

```bash
# Kiểm tra pod status
kubectl get pods -n logging | grep akhq

# Xem logs
kubectl logs -n logging <akhq-pod-name>

# Test connectivity từ AKHQ pod
kubectl exec -it -n logging <akhq-pod-name> -- sh
telnet kafka 9092
nc -zv kafka 9092

# Kiểm tra Kafka service
kubectl get svc -n logging kafka
kubectl get endpoints -n logging kafka

# Kiểm tra config
kubectl get configmap -n logging akhq-config -o yaml
```

**Cách khắc phục:**

```bash
# Sửa connection string trong config
kubectl edit configmap -n logging akhq-config
# akhq.connections.kafka.properties.bootstrap.servers: "kafka:9092"

# Restart AKHQ
kubectl rollout restart deployment -n logging akhq

# Verify Kafka brokers
kubectl exec -it -n logging <kafka-pod-name> -- kafka-broker-api-versions --bootstrap-server localhost:9092