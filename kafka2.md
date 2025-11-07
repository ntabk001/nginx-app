**CÓ**, bạn cần cấu hình Kafka cho Scenario Active-Active Processing. Dưới đây là các cấu hình quan trọng:

## ⚙️ **Kafka Configurations Required**

### **1. Topic Partition Scaling**
```bash
# Kiểm tra current partitions
kafka-topics.sh --bootstrap-server kafka:9092 --topic my-logs --describe

# Tăng partitions nếu cần (không thể giảm)
kafka-topics.sh --bootstrap-server kafka:9092 --topic my-logs \
  --alter --partitions 6  # Ít nhất 3-4 partitions per consumer group
```

### **2. Topic Retention Policy**
```bash
# Set retention phù hợp cho active-active processing
kafka-topics.sh --bootstrap-server kafka:9092 --topic my-logs \
  --alter --config retention.ms=604800000  # 7 days
  --config retention.bytes=1073741824      # 1GB
```

## 🔧 **Consumer Group Configurations**

### **3. Consumer Group Settings**
```properties
# Trong Logstash kafka input
session.timeout.ms=30000
heartbeat.interval.ms=10000
max.poll.interval.ms=300000
auto.offset.reset=latest
```

## 📊 **Capacity Planning Requirements**

### **4. Tính toán Resource Needs**
```bash
# Ước lượng throughput
Expected Messages/sec = 10,000
Consumer Groups = 2 (LS7 + LS8)
Total Consumption = 10,000 × 2 = 20,000 msg/sec

# Partition sizing rule
Recommended Partitions = ceil(Total Throughput / Partition Capacity)
= ceil(20,000 / 5,000) = 4 partitions minimum
```

## 🛠️ **Logstash Configuration Details**

### **Logstash 7**
```ruby
input {
  kafka {
    bootstrap_servers => "kafka1:9092,kafka2:9092"
    topics => ["application-logs"]
    group_id => "logstash-7-active"
    client_id => "logstash7-prod"
    
    # Consumer tuning
    consumer_threads => 3
    auto_offset_reset => "latest"
    session_timeout_ms => 30000
    
    # Performance
    fetch_max_bytes => 10485760
    max_partition_fetch_bytes => 1048576
  }
}

output {
  elasticsearch {
    hosts => ["es7-node:9200"]
    index => "logs-app-7-%{+YYYY.MM.dd}"
  }
}
```

### **Logstash 8**
```ruby
input {
  kafka {
    bootstrap_servers => "kafka1:9092,kafka2:9092"
    topics => ["application-logs"]
    group_id => "logstash-8-active" 
    client_id => "logstash8-prod"
    
    # Consumer tuning
    consumer_threads => 3
    auto_offset_reset => "latest"
    session_timeout_ms => 30000
    
    # ES 8 specific
    decorator_allow_list => "org.logstash.kafka.*"
    
    # Performance
    fetch_max_bytes => 10485760
    max_partition_fetch_bytes => 1048576
  }
}

output {
  elasticsearch {
    hosts => ["es8-node:9200"]
    index => "logs-app-8-%{+YYYY.MM.dd}"
    # ES 8 security features
    user => "logstash_user"
    password => "${LS_PASSWORD}"
    ssl => true
  }
}
```

## 📈 **Kafka Broker Configurations**

### **5. Broker-level Settings**
```properties
# trong server.properties
num.io.threads=8
num.network.threads=3
socket.request.max.bytes=104857600
message.max.bytes=10000120
```

### **6. Consumer Group Coordination**
```bash
# Monitor group coordination
kafka-configs.sh --bootstrap-server kafka:9092 --entity-type brokers --describe
```

## 🚨 **Những điều cần kiểm tra**

### **7. Pre-deployment Checklist**
```bash
# 1. Kiểm tra topic existence
kafka-topics.sh --bootstrap-server kafka:9092 --list | grep application-logs

# 2. Kiểm tra current partitions
kafka-topics.sh --bootstrap-server kafka:9092 --topic application-logs --describe

# 3. Kiểm tra existing consumer groups
kafka-consumer-groups.sh --bootstrap-server kafka:9092 --list

# 4. Kiểm tra network connectivity
telnet kafka1 9092
telnet kafka2 9092
```

### **8. Monitoring Setup**
```bash
# Consumer lag monitoring
kafka-consumer-groups.sh --bootstrap-server kafka:9092 \
  --group logstash-7-active --describe

kafka-consumer-groups.sh --bootstrap-server kafka:9092 \
  --group logstash-8-active --describe
```

## 💡 **Performance Considerations**

### **9. Resource Allocation**
```yaml
# Mỗi Logstash instance cần:
- CPU: 2-4 cores
- Memory: 4-8GB RAM
- Network: 1Gbps+ throughput

# Kafka cluster cần x2 capacity:
- Disk I/O: Higher throughput
- Network: Double the bandwidth
- CPU: Additional processing
```

### **10. Partition Rebalancing Strategy**
```ruby
# Trong Logstash config để tránh rebalancing issues
session_timeout_ms => 30000
max_poll_records => 500
max_poll_interval_ms => 300000
```

## 🎯 **Kết luận**

**CÓ cần cấu hình Kafka** cho Active-Active Processing:

✅ **Bắt buộc**: Different consumer groups  
✅ **Khuyến nghị**: Tăng partitions nếu cần  
✅ **Quan trọng**: Điều chỉnh retention policies  
✅ **Cần thiết**: Monitor consumer lag  
✅ **Nên có**: Capacity planning cho 2x throughput  

Cấu hình đúng sẽ đảm bảo:
- **High availability** với dual processing
- **Performance** không bị degradation  
- **No data loss** trong quá trình xử lý song song
- **Easy rollback** nếu một version có vấn đề

## 🔍 **Direct Kafka Verification Methods**

### **1. So sánh Consumer Group Offsets**

```bash
# Kiểm tra offset của cả 2 consumer groups
kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group logstash-7-active --describe

kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group logstash-8-active --describe
```

**Output sẽ hiển thị:**
```
GROUP              TOPIC           PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG
logstash-7-active  application-logs 0          1500            1500            0
logstash-8-active  application-logs 0          1500            1500            0
```

**Nhận xét:** Nếu `CURRENT-OFFSET` của cả 2 groups bằng `LOG-END-OFFSET` → cả 2 đã xử lý hết messages.

### **2. So sánh Message Count bằng Offset Shell**

```bash
# Lấy tổng số messages trong topic
kafka-run-class.sh kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 \
  --topic application-logs \
  --time -1

# Kết quả: application-logs:0:1500 (1500 messages)

# Kiểm tra current offset của từng group
kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group logstash-7-active --describe --offsets

kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group logstash-8-active --describe --offsets
```

## 📊 **Consumer Group Metrics API**

### **3. Sử dụng Kafka Admin API**

```java
// Python script để verify
from kafka import KafkaAdminClient, KafkaConsumer
from kafka.admin import ConfigResource, ConfigResourceType
import json

def verify_dual_consumption():
    bootstrap_servers = ['kafka1:9092', 'kafka2:9092']
    topic = 'application-logs'
    group7 = 'logstash-7-active'
    group8 = 'logstash-8-active'
    
    admin_client = KafkaAdminClient(bootstrap_servers=bootstrap_servers)
    
    # Lấy thông tin consumer groups
    groups_info = admin_client.describe_consumer_groups([group7, group8])
    
    for group in groups_info:
        print(f"Group: {group.group_id}")
        for member in group.members:
            print(f"  Member: {member.member_id}")
            print(f"  Assignment: {member.assignment}")

verify_dual_consumption()
```

### **4. Real-time Monitoring với kafkacat**

```bash
# Install kafkacat
sudo apt-get install kafkacat

# Monitor consumer groups real-time
kafkacat -b kafka:9092 -L -G logstash-7-active,logstash-8-active

# Get detailed group information
kafkacat -b kafka:9092 -Q -o beginning -e -q \
  -G logstash-7-active application-logs
```

## 🛠️ **Kafka Consumer Lag Monitoring**

### **5. Sử dụng Burrow hoặc Kafdrop**

**Với Kafdrop UI:**
- Truy cập Kafdrop web interface
- Xem Consumer Groups tab
- So sánh lag giữa 2 groups

**Với Burrow:**
```bash
# Check consumer status
curl http://burrow-host:8000/v3/kafka/local/consumer/logstash-7-active/status
curl http://burrow-host:8000/v3/kafka/local/consumer/logstash-8-active/status
```

### **6. JMX Metrics từ Kafka**

```bash
# Sử dụng jconsole hoặc jmxterm
echo "get -b kafka.consumer:type=consumer-fetch-manager-metrics,client-id=logstash-7-* bytes-consumed-rate" | \
  java -jar jmxterm.jar -l localhost:9999

echo "get -b kafka.consumer:type=consumer-fetch-manager-metrics,client-id=logstash-8-* bytes-consumed-rate" | \
  java -jar jmxterm.jar -l localhost:9999
```

## 📈 **Custom Kafka Verification Script**

### **7. Python Script để xác nhận**

```python
from kafka import KafkaConsumer, TopicPartition
from kafka.admin import KafkaAdminClient, ConfigResource, ConfigResourceType

def verify_dual_processing():
    bootstrap_servers = ['kafka:9092']
    topic = 'application-logs'
    group7 = 'logstash-7-active'
    group8 = 'logstash-8-active'
    
    # Tạo consumers để check offsets
    consumer7 = KafkaConsumer(
        bootstrap_servers=bootstrap_servers,
        group_id=group7,
        enable_auto_commit=False
    )
    
    consumer8 = KafkaConsumer(
        bootstrap_servers=bootstrap_servers,
        group_id=group8, 
        enable_auto_commit=False
    )
    
    # Lấy partition info
    partitions = consumer7.partitions_for_topic(topic)
    topic_partitions = [TopicPartition(topic, p) for p in partitions]
    
    print(f"Topic: {topic}, Partitions: {partitions}")
    
    # Check committed offsets
    committed7 = consumer7.committed(TopicPartition(topic, 0))
    committed8 = consumer8.committed(TopicPartition(topic, 0))
    
    print(f"Group {group7} committed offset: {committed7}")
    print(f"Group {group8} committed offset: {committed8}")
    
    # Lấy end offset (last message)
    consumer7.assign(topic_partitions)
    end_offsets = consumer7.end_offsets(topic_partitions)
    
    print(f"Topic end offsets: {end_offsets}")
    
    # Tính toán lag
    lag7 = end_offsets[TopicPartition(topic, 0)] - (committed7 or 0)
    lag8 = end_offsets[TopicPartition(topic, 0)] - (committed8 or 0)
    
    print(f"Group {group7} lag: {lag7}")
    print(f"Group {group8} lag: {lag8}")
    
    # Verification logic
    if lag7 == 0 and lag8 == 0:
        print("✅ CẢ HAI groups đã xử lý hết messages")
        print("✅ Mỗi message được xử lý 2 lần")
    else:
        print("⏳ Một hoặc cả hai groups vẫn đang xử lý")
    
    consumer7.close()
    consumer8.close()

verify_dual_processing()
```

### **8. Bash Script để monitoring**

```bash
#!/bin/bash

KAFKA_HOST="localhost:9092"
TOPIC="application-logs"
GROUP7="logstash-7-active"
GROUP8="logstash-8-active"

echo "=== Dual Processing Verification ==="

# Lấy topic end offsets
END_OFFSETS=$(kafka-run-class.sh kafka.tools.GetOffsetShell \
  --broker-list $KAFKA_HOST \
  --topic $TOPIC \
  --time -1 | awk -F ":" '{sum += $3} END {print sum}')

echo "Total messages in topic: $END_OFFSETS"

# Lấy current offsets của từng group
OFFSET7=$(kafka-consumer-groups.sh --bootstrap-server $KAFKA_HOST \
  --group $GROUP7 --describe | grep $TOPIC | awk '{sum += $4} END {print sum}')

OFFSET8=$(kafka-consumer-groups.sh --bootstrap-server $KAFKA_HOST \
  --group $GROUP8 --describe | grep $TOPIC | awk '{sum += $4} END {print sum}')

echo "Group $GROUP7 processed: $OFFSET7 messages"
echo "Group $GROUP8 processed: $OFFSET8 messages"

# Verification
if [ "$OFFSET7" -eq "$END_OFFSETS" ] && [ "$OFFSET8" -eq "$END_OFFSETS" ]; then
    echo "✅ VERIFIED: Each message processed TWICE"
    echo "✅ Total processing: $((OFFSET7 + OFFSET8)) events"
    echo "✅ Unique messages: $END_OFFSETS"
else
    echo "⏳ Processing in progress..."
    echo "Group $GROUP7 progress: $((OFFSET7 * 100 / END_OFFSETS))%"
    echo "Group $GROUP8 progress: $((OFFSET8 * 100 / END_OFFSETS))%"
fi
```

## 🎯 **Real-time Monitoring Command**

### **9. Continuous Monitoring**

```bash
# Watch consumer groups real-time
watch -n 5 "kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group logstash-7-active --describe && \
  kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group logstash-8-active --describe"
```

### **10. Kafka Topics Console**

```bash
# Sử dụng Kafka console consumer để verify
kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic __consumer_offsets --formatter "kafka.coordinator.group.GroupMetadataManager\$OffsetsMessageFormatter" \
  --from-beginning | grep -E "(logstash-7-active|logstash-8-active)"
```

## 💡 **Quick Verification**

```bash
# One-liner verification
echo "Group7: $(kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group logstash-7-active --describe | awk '/application-logs/ {sum+=$4} END{print sum}') messages | Group8: $(kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group logstash-8-active --describe | awk '/application-logs/ {sum+=$4} END{print sum}') messages"
```

## ✅ **Kết luận**

**HOÀN TOÀN CÓ THỂ** xác nhận trên Kafka thông qua:
- ✅ **Consumer group offsets** so sánh
- ✅ **Lag monitoring** = 0 cho cả 2 groups  
- ✅ **Message count verification**
- ✅ **Real-time JMX metrics**

**Dấu hiệu xác nhận thành công:**
- `CURRENT-OFFSET` = `LOG-END-OFFSET` cho cả 2 groups
- `LAG` = 0 cho cả 2 groups  
- Tổng processed messages = 2 × (topic message count)

Phương pháp Kafka-based này **không cần truy cập Elasticsearch** và cho kết quả **chính xác 100%**.
