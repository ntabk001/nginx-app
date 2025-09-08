# Kiểm tra trạng thái Kafka Cluster với xác thực User/Password

## 1. Exec vào Pod Kafka

```bash
# Exec vào pod Kafka
kubectl exec -it <kafka-pod-name> -n <namespace> -- bash

# Hoặc nếu sử dụng container cụ thể
kubectl exec -it <kafka-pod-name> -c kafka -n <namespace> -- bash
```

## 2. Phương pháp xác thực

### Phương pháp 1: Sử dụng file client.properties (khuyến nghị)

Tạo file `/opt/kafka/config/client.properties`:

```properties
# Authentication
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required \
  username="<username>" \
  password="<password>";

# Nếu sử dụng SSL
# security.protocol=SASL_SSL
# ssl.truststore.location=/path/to/truststore.jks
# ssl.truststore.password=<truststore-password>
```

### Phương pháp 2: Sử dụng KAFKA_OPTS Environment Variable

```bash
# Set environment variable trước khi chạy command
export KAFKA_OPTS="-Djava.security.auth.login.config=/opt/kafka/config/kafka_jaas.conf"

# Hoặc inline với command
KAFKA_OPTS="-Djava.security.auth.login.config=/opt/kafka/config/kafka_jaas.conf" \
kafka-topics.sh --bootstrap-server localhost:9092 --list
```

### Phương pháp 3: Sử dụng System Properties trực tiếp

```bash
# Truyền trực tiếp các properties vào command
kafka-topics.sh --bootstrap-server localhost:9092 \
  --command-config <(cat <<EOF
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="myuser" password="mypass";
EOF
) --list
```

### Phương pháp 4: Sử dụng JAAS Config File

Tạo file `/opt/kafka/config/kafka_jaas.conf`:

```
KafkaClient {
  org.apache.kafka.common.security.plain.PlainLoginModule required
  username="myuser"
  password="mypass";
};
```

Sau đó export:
```bash
export KAFKA_OPTS="-Djava.security.auth.login.config=/opt/kafka/config/kafka_jaas.conf"
```

### Phương pháp 5: Inline JAAS Configuration

```bash
# Sử dụng producer properties inline
kafka-console-producer.sh --bootstrap-server localhost:9092 \
  --topic test-topic \
  --producer-property security.protocol=SASL_PLAINTEXT \
  --producer-property sasl.mechanism=PLAIN \
  --producer-property sasl.jaas.config='org.apache.kafka.common.security.plain.PlainLoginModule required username="myuser" password="mypass";'

# Consumer tương tự
kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic test-topic \
  --consumer-property security.protocol=SASL_PLAINTEXT \
  --consumer-property sasl.mechanism=PLAIN \
  --consumer-property sasl.jaas.config='org.apache.kafka.common.security.plain.PlainLoginModule required username="myuser" password="mypass";'
```

## 3. Kiểm tra trạng thái Cluster Kafka

### 3.1. Kiểm tra Broker Status

```bash
# Liệt kê các broker trong cluster
kafka-broker-api-versions.sh --bootstrap-server localhost:9092 \
  --command-config /opt/kafka/config/client.properties

# Kiểm tra metadata cluster
kafka-metadata-shell.sh --snapshot /var/kafka-logs/__cluster_metadata-0/00000000000000000000.log
```

### 3.2. Sử dụng kafka-topics để kiểm tra

```bash
# Liệt kê topics với authentication
kafka-topics.sh --bootstrap-server localhost:9092 \
  --list \
  --command-config /opt/kafka/config/client.properties

# Kiểm tra chi tiết topic
kafka-topics.sh --bootstrap-server localhost:9092 \
  --describe \
  --command-config /opt/kafka/config/client.properties

# Sử dụng inline properties (không cần file config)
kafka-topics.sh --bootstrap-server localhost:9092 \
  --list \
  --command-config <(echo "security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username=\"myuser\" password=\"mypass\";")
```

## 4. Các command kiểm tra trạng thái cluster

### 4.1. Kiểm tra Cluster Health

```bash
# Kiểm tra cluster metadata
kafka-log-dirs.sh --bootstrap-server localhost:9092 \
  --command-config /opt/kafka/config/client.properties \
  --describe

# Kiểm tra consumer groups
kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --list \
  --command-config /opt/kafka/config/client.properties

# Kiểm tra replica status
kafka-replica-verification.sh --broker-list localhost:9092 \
  --topic-white-list ".*"
```

### 4.2. Kiểm tra Log và Performance

```bash
# Kiểm tra log size và segments
kafka-log-dirs.sh --bootstrap-server localhost:9092 \
  --command-config /opt/kafka/config/client.properties \
  --describe \
  --json

# Test producer/consumer với timeout
timeout 10s kafka-console-producer.sh --bootstrap-server localhost:9092 \
  --topic test-topic \
  --producer.config /opt/kafka/config/client.properties

timeout 10s kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic test-topic \
  --from-beginning \
  --consumer.config /opt/kafka/config/client.properties
```

### 4.3. Kiểm tra Performance Metrics

```bash
# Kiểm tra producer performance
kafka-producer-perf-test.sh --topic test-topic \
  --num-records 1000 \
  --record-size 1024 \
  --throughput 100 \
  --producer-props bootstrap.servers=localhost:9092 \
  security.protocol=SASL_PLAINTEXT \
  sasl.mechanism=PLAIN \
  sasl.jaas.config='org.apache.kafka.common.security.plain.PlainLoginModule required username="myuser" password="mypass";'

# Kiểm tra consumer performance  
kafka-consumer-perf-test.sh --topic test-topic \
  --bootstrap-server localhost:9092 \
  --messages 1000 \
  --consumer.config /opt/kafka/config/client.properties
```

## 5. Troubleshooting khi Cluster gặp lỗi

### 5.1. Kiểm tra Network và Connection

```bash
# Test kết nối đến broker
telnet localhost 9092

# Kiểm tra port listening
netstat -tlnp | grep 9092
ss -tlnp | grep 9092

# Kiểm tra DNS resolution (nếu cần)
nslookup kafka-service
dig kafka-service

# Test với kafkacat (nếu có)
kafkacat -b localhost:9092 -L \
  -X security.protocol=SASL_PLAINTEXT \
  -X sasl.mechanism=PLAIN \
  -X sasl.username=myuser \
  -X sasl.password=mypass
```

### 5.2. Kiểm tra Logs

```bash
# Kiểm tra Kafka server logs
tail -f /opt/kafka/logs/server.log

# Kiểm tra controller logs
tail -f /opt/kafka/logs/controller.log

# Kiểm tra log4j logs
tail -f /opt/kafka/logs/kafkaServer.out

# Tìm lỗi authentication
grep -i "authentication\|sasl\|login" /opt/kafka/logs/server.log

# Kiểm tra lỗi gần nhất
tail -100 /opt/kafka/logs/server.log | grep -i error
```

### 5.3. Kiểm tra JVM và Resources

```bash
# Kiểm tra Java processes
jps -v | grep kafka

# Kiểm tra memory usage
free -h
df -h

# Kiểm tra JVM heap
jstat -gc $(pgrep -f kafka.Kafka)

# Kiểm tra file descriptors
lsof -p $(pgrep -f kafka.Kafka) | wc -l

# Kiểm tra threads
ps -eLf | grep kafka | wc -l
```

### 5.4. Kiểm tra Configuration

```bash
# Kiểm tra server properties
cat /opt/kafka/config/server.properties | grep -E "(broker.id|log.dirs|listeners|security)"

# Validate configuration
kafka-configs.sh --bootstrap-server localhost:9092 \
  --command-config /opt/kafka/config/client.properties \
  --entity-type brokers \
  --describe

# Kiểm tra topic configuration
kafka-configs.sh --bootstrap-server localhost:9092 \
  --command-config /opt/kafka/config/client.properties \
  --entity-type topics \
  --entity-name <topic-name> \
  --describe
```

## 6. Advanced Troubleshooting Commands

### 6.1. Kiểm tra Offset và Consumer Lag

```bash
# Kiểm tra consumer lag detail
kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --describe \
  --group <consumer-group-name> \
  --command-config /opt/kafka/config/client.properties

# Reset consumer offset
kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --reset-offsets \
  --group <consumer-group-name> \
  --topic <topic-name> \
  --to-earliest \
  --command-config /opt/kafka/config/client.properties

# Kiểm tra earliest và latest offset
kafka-run-class.sh kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 \
  --topic <topic-name> \
  --time -1
```

### 6.2. Kiểm tra Partition và Replica

```bash
# Kiểm tra under-replicated partitions
kafka-topics.sh --bootstrap-server localhost:9092 \
  --describe \
  --under-replicated-partitions \
  --command-config /opt/kafka/config/client.properties

# Kiểm tra unavailable partitions
kafka-topics.sh --bootstrap-server localhost:9092 \
  --describe \
  --unavailable-partitions \
  --command-config /opt/kafka/config/client.properties

# Preferred replica election
kafka-preferred-replica-election.sh --bootstrap-server localhost:9092 \
  --command-config /opt/kafka/config/client.properties
```

### 6.3. Log Segment Analysis

```bash
# Kiểm tra log segments
kafka-dump-log.sh --files /var/kafka-logs/<topic-partition>/00000000000000000000.log \
  --print-data-log

# Kiểm tra index files
kafka-dump-log.sh --files /var/kafka-logs/<topic-partition>/00000000000000000000.index

# Verify log integrity
kafka-log-dirs.sh --bootstrap-server localhost:9092 \
  --command-config /opt/kafka/config/client.properties \
  --describe \
  --json | jq '.brokers[].logDirs[].error'
```

## 7. Logstash Integration Check

### 7.1. Test Connection từ Logstash

```bash
# Exec vào Logstash pod
kubectl exec -it <logstash-pod-name> -n <namespace> -- bash

# Test với ruby script
/usr/share/logstash/bin/ruby -e "
require 'kafka'
kafka = Kafka.new(['kafka-service:9092'], 
  sasl_plain_username: 'myuser',
  sasl_plain_password: 'mypass',
  security_protocol: :sasl_plaintext
)
puts kafka.topics
"
```

### 7.2. Logstash Configuration Examples

```yaml
# Logstash input từ Kafka
input {
  kafka {
    bootstrap_servers => "kafka-service:9092"
    topics => ["input-topic"]
    security_protocol => "SASL_PLAINTEXT"
    sasl_mechanism => "PLAIN"
    jaas_path => "/usr/share/logstash/config/kafka_jaas.conf"
    # Hoặc sử dụng inline
    # sasl_plain_username => "myuser"
    # sasl_plain_password => "mypass"
  }
}

# Logstash output đến Kafka
output {
  kafka {
    bootstrap_servers => "kafka-service:9092"
    topic_id => "output-topic"
    security_protocol => "SASL_PLAINTEXT"
    sasl_mechanism => "PLAIN"
    jaas_path => "/usr/share/logstash/config/kafka_jaas.conf"
  }
}
```

## 8. Monitoring và Health Check Scripts

### 8.1. Cluster Health Check Script

```bash
#!/bin/bash
# cluster-health-check.sh

KAFKA_HOME="/opt/kafka"
CONFIG_FILE="/opt/kafka/config/client.properties"
BOOTSTRAP_SERVER="localhost:9092"
LOG_FILE="/tmp/kafka-health-$(date +%Y%m%d).log"

function log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

log_message "=== Kafka Cluster Health Check Started ==="

# Check if Kafka is running
if ! pgrep -f "kafka.Kafka" > /dev/null; then
    log_message "ERROR: Kafka process not running"
    exit 1
fi

# Check broker connectivity
log_message "Checking broker connectivity..."
if timeout 10s $KAFKA_HOME/bin/kafka-broker-api-versions.sh \
    --bootstrap-server $BOOTSTRAP_SERVER \
    --command-config $CONFIG_FILE &>/dev/null; then
    log_message "SUCCESS: Broker is accessible"
else
    log_message "ERROR: Cannot connect to broker"
    exit 1
fi

# Check topics count
TOPIC_COUNT=$($KAFKA_HOME/bin/kafka-topics.sh \
    --bootstrap-server $BOOTSTRAP_SERVER \
    --list --command-config $CONFIG_FILE 2>/dev/null | wc -l)
log_message "Total topics: $TOPIC_COUNT"

# Check consumer groups
GROUP_COUNT=$($KAFKA_HOME/bin/kafka-consumer-groups.sh \
    --bootstrap-server $BOOTSTRAP_SERVER \
    --list --command-config $CONFIG_FILE 2>/dev/null | wc -l)
log_message "Total consumer groups: $GROUP_COUNT"

# Check under-replicated partitions
UNDER_REPLICATED=$($KAFKA_HOME/bin/kafka-topics.sh \
    --bootstrap-server $BOOTSTRAP_SERVER \
    --describe --under-replicated-partitions \
    --command-config $CONFIG_FILE 2>/dev/null | wc -l)

if [ $UNDER_REPLICATED -gt 0 ]; then
    log_message "WARNING: $UNDER_REPLICATED under-replicated partitions found"
else
    log_message "SUCCESS: No under-replicated partitions"
fi

# Check disk space
DISK_USAGE=$(df -h /var/kafka-logs | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    log_message "WARNING: Disk usage is ${DISK_USAGE}%"
else
    log_message "INFO: Disk usage is ${DISK_USAGE}%"
fi

log_message "=== Health Check Completed ==="
```

### 8.2. Performance Monitoring Script

```bash
#!/bin/bash
# kafka-performance-monitor.sh

KAFKA_HOME="/opt/kafka"
CONFIG_FILE="/opt/kafka/config/client.properties"
BOOTSTRAP_SERVER="localhost:9092"
TEST_TOPIC="performance-test-topic"

# Create test topic if not exists
$KAFKA_HOME/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVER \
    --create --if-not-exists \
    --topic $TEST_TOPIC \
    --partitions 3 \
    --replication-factor 1 \
    --command-config $CONFIG_FILE

echo "=== Producer Performance Test ==="
$KAFKA_HOME/bin/kafka-producer-perf-test.sh \
    --topic $TEST_TOPIC \
    --num-records 1000 \
    --record-size 1024 \
    --throughput 100 \
    --producer-props bootstrap.servers=$BOOTSTRAP_SERVER \
    security.protocol=SASL_PLAINTEXT \
    sasl.mechanism=PLAIN \
    sasl.jaas.config='org.apache.kafka.common.security.plain.PlainLoginModule required username="myuser" password="mypass";'

echo "=== Consumer Performance Test ==="
timeout 30s $KAFKA_HOME/bin/kafka-consumer-perf-test.sh \
    --topic $TEST_TOPIC \
    --bootstrap-server $BOOTSTRAP_SERVER \
    --messages 1000 \
    --consumer.config $CONFIG_FILE

# Cleanup
$KAFKA_HOME/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVER \
    --delete --topic $TEST_TOPIC \
    --command-config $CONFIG_FILE
```

## 9. Common Issues và Solutions

### Issue 1: Authentication Failed
```bash
# Kiểm tra credentials
echo "Testing authentication..."
kafka-console-producer.sh --bootstrap-server localhost:9092 \
    --topic __consumer_offsets \
    --timeout 5000 \
    --producer-property security.protocol=SASL_PLAINTEXT \
    --producer-property sasl.mechanism=PLAIN \
    --producer-property sasl.jaas.config='org.apache.kafka.common.security.plain.PlainLoginModule required username="myuser" password="mypass";' \
    < /dev/null

# Kiểm tra JAAS config syntax
java -Djava.security.auth.login.config=/opt/kafka/config/kafka_jaas.conf \
     -cp /opt/kafka/libs/* \
     org.apache.kafka.common.security.authenticator.SaslClientAuthenticator
```

### Issue 2: Network Connectivity
```bash
# Multi-step network test
echo "1. Testing basic connectivity..."
nc -zv localhost 9092

echo "2. Testing SASL handshake..."
timeout 5s openssl s_client -connect localhost:9092 -verify_return_error 2>/dev/null

echo "3. Testing with kafkacat (if available)..."
echo "test" | kafkacat -b localhost:9092 -t test-topic \
    -X security.protocol=SASL_PLAINTEXT \
    -X sasl.mechanism=PLAIN \
    -X sasl.username=myuser \
    -X sasl.password=mypass
```

### Issue 3: Resource Issues
```bash
# Comprehensive resource check
echo "=== System Resources ==="
echo "Memory:"
free -h
echo "Disk:"
df -h /var/kafka-logs
echo "File descriptors:"
lsof -p $(pgrep -f kafka.Kafka) | wc -l
echo "Network connections:"
ss -tan | grep :9092 | wc -l
echo "JVM Heap:"
jstat -gc $(pgrep -f kafka.Kafka)
```

## 10. Quick Reference Commands

```bash
# Nhanh chóng kiểm tra cluster status
alias kstatus='kafka-topics.sh --bootstrap-server localhost:9092 --list --command-config /opt/kafka/config/client.properties'

# Kiểm tra consumer groups
alias kgroups='kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list --command-config /opt/kafka/config/client.properties'

# Kiểm tra under-replicated partitions
alias kunder='kafka-topics.sh --bootstrap-server localhost:9092 --describe --under-replicated-partitions --command-config /opt/kafka/config/client.properties'

# Test producer nhanh
alias kprod='kafka-console-producer.sh --bootstrap-server localhost:9092 --topic test --producer.config /opt/kafka/config/client.properties'

# Test consumer nhanh  
alias kcons='kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic test --from-beginning --consumer.config /opt/kafka/config/client.properties'
```

---

## Tổng kết

Có **5 phương pháp chính** để xác thực với Kafka:
1. **File client.properties** (khuyến nghị cho production)
2. **Environment variable KAFKA_OPTS**  
3. **System properties trực tiếp**
4. **JAAS config file**
5. **Inline properties** (tiện cho testing)

Mỗi phương pháp đều có ưu nhược điểm riêng. File config properties là phương pháp an toàn nhất cho production environment, trong khi inline properties tiện lợi cho testing và troubleshooting nhanh.
