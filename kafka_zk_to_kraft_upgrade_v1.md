# Nâng cấp Kafka 3.9.2 + ZooKeeper 3.9.5 lên Kafka 4.4.0 (KRaft) – giữ nguyên dữ liệu

> Phiên bản tài liệu: v1 – 25/11/2026
> Phạm vi: cluster 3 server, đang chạy Kafka 3.9.2 (ZooKeeper mode) + ZooKeeper 3.9.5; đích là Kafka 4.4.0 chạy KRaft (HA bằng 3 controller).
> Hình thức: rolling (không downtime toàn cluster), dữ liệu topic/offset/ACL được giữ nguyên.

---

## 1. Tổng quan và nguyên tắc quan trọng

### 1.1. Vì sao không thể nâng cấp thẳng một bước

- Kafka 4.0 trở lên **đã loại bỏ hoàn toàn ZooKeeper** và cả mã migration ZK → KRaft. Broker 4.x chỉ chạy được ở KRaft mode.
- Việc chuyển metadata từ ZooKeeper sang KRaft **bắt buộc thực hiện trên bản cầu nối (bridge release) là Kafka 3.9.x**. Cluster đang ở 3.9.2 nên đã đúng bản cầu nối.
- Do đó quy trình gồm **2 giai đoạn tách biệt**:
  1. **Giai đoạn A** – Migrate ZooKeeper → KRaft, vẫn dùng binary Kafka **3.9.2**.
  2. **Giai đoạn B** – Nâng cấp rolling binary từ **3.9.2 (KRaft) → 4.4.0**.

Tài liệu Apache xác nhận KRaft cluster từ 3.3.x trở lên có thể nâng thẳng lên 4.4.0 (không cần qua 4.0/4.1/4.2/4.3).

### 1.2. Các điểm cần nhớ

| # | Điểm cần nhớ |
|---|---|
| 1 | Chỉ finalize migration (bỏ ZK) **sau** khi kiểm tra kỹ. Sau khi finalize **không thể quay lại ZooKeeper**. |
| 2 | Trong lúc đang migrate, **không đổi `metadata.version` / `inter.broker.protocol.version`**. |
| 3 | `node.id` của controller KRaft **phải khác** mọi `broker.id` hiện có (broker và controller dùng chung không gian ID). |
| 4 | Broker khi chuyển sang KRaft **phải giữ nguyên ID** cũ (`broker.id` → `node.id` cùng giá trị) và **giữ nguyên `log.dirs`** để dữ liệu không đổi. |
| 5 | Không dùng *combined mode* (`broker,controller`) cho migration và cho môi trường production; tách riêng process controller và process broker (có thể cùng chạy trên 3 server). |
| 6 | Kafka 4.x broker yêu cầu **Java 17+**. Client tối thiểu **2.1+**. |
| 7 | Metadata của 4.4 **không hỗ trợ downgrade** sau khi finalize (`kafka-features.sh upgrade`). Hãy soak đủ lâu trước khi finalize. |
| 8 | Kafka 4.4 (KIP-1170): thư mục format bằng `kafka-storage` không còn tương thích tiến – broker phải **cùng hoặc mới hơn** phiên bản tool đã format. Luôn format node mới bằng tool 4.4.0 và không chạy broker bản cũ hơn trên thư mục đó. |

### 1.3. Lưu ý bảo mật JDK (CVE-2026-114938 "Java4Shell")

Ngày 19/11/2026 Apache Kafka công bố lỗi nằm ở JDK (không phải Kafka): ảnh hưởng JDK 17.0.6–17.0.21, 21–21.0.13, 25–25.0.5... chạy trên CPU x86-64 có AVX-512 VBMI. Khi cài/nâng JDK 17 cho Kafka:

- Dùng bản JDK đã vá (17.0.21.1 trở lên – kiểm tra bản vá cụ thể theo advisory của vendor JDK), **hoặc**
- Tạm thời thêm cờ `-XX:-UseBASE64Intrinsics` vào `KAFKA_OPTS` (cờ này chỉ dùng trên Java 11+; Java 8 sẽ không khởi động được nếu thêm cờ).

---

## 2. Giả định môi trường (điều chỉnh cho đúng thực tế)

| Thành phần | Giá trị giả định |
|---|---|
| 3 server | `kafka01`, `kafka02`, `kafka03` (thay bằng hostname/IP thật) |
| ZooKeeper | 3 node, port client `2181`, chạy cùng 3 server |
| Kafka broker hiện tại | `broker.id` = 1, 2, 3 ; listener `PLAINTEXT://:9092` |
| Thư mục cài Kafka | `/opt/kafka` (symlink tới `/opt/kafka_2.13-3.9.2`) |
| Thư mục dữ liệu broker | `/data/kafka` (giữ nguyên, **không xóa, không format**) |
| Thư mục dữ liệu controller (mới) | `/data/kafka-controller` |
| User chạy dịch vụ | `kafka` |
| Dịch vụ systemd | `zookeeper.service`, `kafka.service` (broker), `kafka-controller.service` (tạo mới) |
| Node ID controller (mới) | 3001, 3002, 3003 |
| Quorum | **static quorum** (`controller.quorum.voters`) – ổn định nhất cho migration, có thể chuyển sang dynamic ở bước tùy chọn cuối tài liệu |

> Nếu cluster dùng SASL/SSL, thêm các cấu hình listener/security tương ứng vào controller và broker (map `CONTROLLER` sang protocol đang dùng). Phần mẫu dưới đây dùng PLAINTEXT để dễ đọc.

---

## 3. Lộ trình tổng thể

| Phase | Nội dung | Binary | Ảnh hưởng |
|---|---|---|---|
| 0 | Kiểm tra điều kiện tiên quyết | – | Không |
| 1 | Backup toàn bộ (ZK, config, metadata, offsets) | – | Không |
| 2 | Chuẩn hóa: Java 17, IBP=3.9, rolling restart broker | 3.9.2 | Rolling restart |
| 3 | Dựng 3 KRaft controller (migration enabled) | 3.9.2 | Không |
| 4 | Đưa broker vào migration mode (rolling) → metadata được copy sang KRaft | 3.9.2 | Rolling restart |
| 5 | Chuyển từng broker sang KRaft mode (rolling) | 3.9.2 | Rolling restart |
| 6 | Finalize migration, tắt ZooKeeper | 3.9.2 | Rolling restart controller |
| 7 | Soak (khuyến nghị vài ngày) | 3.9.2 | Không |
| 8 | Nâng cấp lên 4.4.0: controller trước, broker sau (rolling) | 4.4.0 | Rolling restart |
| 9 | Finalize feature version 4.4 | 4.4.0 | Không |
| 10 | (Tùy chọn) chuyển static quorum → dynamic quorum | 4.4.0 | Rolling restart |

Thời gian dự kiến: 1 phiên (4–6 giờ) cho Phase 0–6, 1 phiên (2–3 giờ) cho Phase 8–9, tùy dung lượng dữ liệu và thời gian restart broker.

---

## 4. Phase 0 – Kiểm tra điều kiện tiên quyết

### 4.1. Checklist

- [ ] Kafka đang là **3.9.2** trên cả 3 broker (yêu cầu tối thiểu 3.9.1 để migrate).
- [ ] `inter.broker.protocol.version` hiện là `3.9` (nếu chưa, xử lý ở Phase 2).
- [ ] Không có partition **under-replicated** / **offline** / đang **reassignment**.
- [ ] Không có topic đang chờ xóa (pending deletion) trong ZK (`/admin/delete_topics` rỗng).
- [ ] Mọi topic có `replication.factor >= 2` (khuyến nghị 3) để broker restart không mất availability.
- [ ] Client (producer/consumer/Connect/Streams/MirrorMaker, thư viện không thuộc Apache) **>= 2.1** – Kafka 4.0 đã bỏ các API version cũ (KIP-896).
- [ ] Không dùng tính năng đã bị gỡ ở 4.x (xem mục 11.2).
- [ ] Nếu `log.dirs` có **nhiều thư mục (JBOD)**: đọc lưu ý KAFKA-16431 – broker có thư mục hỏng sẽ tắt trong lúc migration. Đảm bảo các thư mục đều khỏe trước khi bắt đầu.
- [ ] Nếu có `alter.config.policy.class.name` tự viết: xem KIP-1252 (có cờ tương thích ở 3.9.2).
- [ ] Nếu ZK có bật SASL/ACL hoặc từng chạy ZooKeeper Security Migration Tool: xem lưu ý KAFKA-19480 ở Phase 3 (node `/migration` hỏng làm migration bị treo).
- [ ] Đã có cửa sổ bảo trì, kênh thông báo cho team ứng dụng.
- [ ] Đã tải sẵn `kafka_2.13-4.4.0.tgz` và kiểm tra chữ ký/SHA512 (để sẵn trên 3 server nhưng **chưa dùng** đến Phase 8).
- [ ] Đã chuẩn bị JDK 17 đã vá (mục 1.3).

### 4.2. Script kiểm tra nhanh – `00_precheck.sh`

```bash
#!/usr/bin/env bash
# Script kiểm tra trước khi nâng cấp; chạy trên 1 server bất kỳ
set -u

# Địa chỉ broker và zookeeper (sửa cho đúng môi trường)
BOOTSTRAP="kafka01:9092,kafka02:9092,kafka03:9092"
ZK="kafka01:2181,kafka02:2181,kafka03:2181"
KAFKA_HOME="/opt/kafka"

echo "[INFO] Checking Java version"
java -version 2>&1 | head -n 1   # In phiên bản Java đang dùng

echo "[INFO] Checking Kafka broker versions"
"$KAFKA_HOME"/bin/kafka-broker-api-versions.sh --bootstrap-server "$BOOTSTRAP" 2>/dev/null \
  | grep -E "^[a-zA-Z0-9.-]+:[0-9]+ \(id:" || echo "[WARN] Cannot read broker list"   # Liệt kê broker đang sống

echo "[INFO] Reading cluster id from ZooKeeper"
"$KAFKA_HOME"/bin/zookeeper-shell.sh "${ZK%%,*}" get /cluster/id 2>/dev/null | grep -E '"id"' \
  || echo "[ERROR] Cannot read /cluster/id"   # Lấy cluster id, cần dùng ở Phase 3

echo "[INFO] Checking under-replicated partitions"
URP=$("$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe --under-replicated-partitions 2>/dev/null)
if [ -z "$URP" ]; then echo "[OK] No under-replicated partitions"; else echo "[ERROR] Under-replicated partitions found:"; echo "$URP"; fi

echo "[INFO] Checking unavailable partitions"
UNAV=$("$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe --unavailable-partitions 2>/dev/null)
if [ -z "$UNAV" ]; then echo "[OK] No unavailable partitions"; else echo "[ERROR] Unavailable partitions found:"; echo "$UNAV"; fi

echo "[INFO] Checking pending topic deletions in ZooKeeper"
"$KAFKA_HOME"/bin/zookeeper-shell.sh "${ZK%%,*}" ls /admin/delete_topics 2>/dev/null | tail -n 1   # Kỳ vọng: []

echo "[INFO] Checking ongoing partition reassignments"
"$KAFKA_HOME"/bin/kafka-reassign-partitions.sh --bootstrap-server "$BOOTSTRAP" --list 2>/dev/null   # Kỳ vọng: không có reassignment

echo "[INFO] Checking topics with replication factor < 2"
"$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe 2>/dev/null \
  | awk '/ReplicationFactor:/ { for (i=1;i<=NF;i++) if ($i=="ReplicationFactor:" && $(i+1)<2) print "[WARN] " $0 }'   # Cảnh báo topic RF thấp

echo "[DONE] Pre-check finished"
```

---

## 5. Phase 1 – Backup

Backup phải xong **trước khi** thay đổi bất kỳ cấu hình nào.

### 5.1. Những gì cần backup

| Đối tượng | Cách backup |
|---|---|
| Cấu hình Kafka (`server.properties`, `log4j.properties`, JAAS, keystore...) | Copy thư mục `config` + unit systemd |
| Dữ liệu ZooKeeper (`dataDir`, `dataLogDir`) + `zoo.cfg` | `tar` từ **một follower** (hoặc dừng tạm 1 node ZK để copy – quorum 3 node vẫn đạt) |
| Cấu trúc topic, config topic, ACL, quota, consumer-group offsets | Xuất ra file text bằng CLI |
| End offsets từng partition (để so sánh trước/sau) | `kafka-get-offsets.sh` |
| Dữ liệu log (`/data/kafka`) | Với dữ liệu lớn: snapshot LVM/storage hoặc đảm bảo replication factor >= 3; nếu có điều kiện, backup lạnh từng broker (dừng broker, copy) |

> Dữ liệu topic nằm trong `log.dirs` của broker và **không bị thay đổi** bởi migration. Backup log dir là biện pháp an toàn thêm, không bắt buộc nếu RF>=3 và ISR đầy đủ.

### 5.2. Script backup metadata – `01_backup.sh`

```bash
#!/usr/bin/env bash
# Script backup cấu hình và metadata trước khi nâng cấp; chạy trên từng server
set -u

KAFKA_HOME="/opt/kafka"
BOOTSTRAP="kafka01:9092,kafka02:9092,kafka03:9092"
BACKUP_DIR="/backup/kafka-upgrade-$(date +%Y%m%d_%H%M%S)"
CONF_DIR="/opt/kafka/config"
ZK_DATA_DIR="/data/zookeeper"      # Sửa theo dataDir trong zoo.cfg

mkdir -p "$BACKUP_DIR" || { echo "[ERROR] Cannot create $BACKUP_DIR"; exit 1; }
echo "[INFO] Backup directory: $BACKUP_DIR"

echo "[INFO] Backing up Kafka config"
tar czf "$BACKUP_DIR/kafka-config.tgz" "$CONF_DIR" /etc/systemd/system/kafka*.service /etc/systemd/system/zookeeper*.service 2>/dev/null \
  && echo "[OK] Kafka config saved" || echo "[WARN] Some config files were not found"   # Cấu hình + unit systemd

echo "[INFO] Backing up ZooKeeper data directory"
tar czf "$BACKUP_DIR/zookeeper-data.tgz" "$ZK_DATA_DIR" 2>/dev/null \
  && echo "[OK] ZooKeeper data saved" || echo "[WARN] ZooKeeper data not found on this host"   # Dữ liệu ZK

echo "[INFO] Exporting topic descriptions"
"$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe > "$BACKUP_DIR/topics-describe.txt" \
  && echo "[OK] Topics exported" || echo "[ERROR] Topic export failed"   # Cấu trúc topic/partition/replica

echo "[INFO] Exporting topic configs"
"$KAFKA_HOME"/bin/kafka-configs.sh --bootstrap-server "$BOOTSTRAP" --describe --entity-type topics > "$BACKUP_DIR/topic-configs.txt" 2>&1 \
  && echo "[OK] Topic configs exported" || echo "[WARN] Topic config export failed"   # Config override từng topic

echo "[INFO] Exporting broker configs"
"$KAFKA_HOME"/bin/kafka-configs.sh --bootstrap-server "$BOOTSTRAP" --describe --entity-type brokers > "$BACKUP_DIR/broker-configs.txt" 2>&1 \
  && echo "[OK] Broker configs exported" || echo "[WARN] Broker config export failed"   # Dynamic broker config

echo "[INFO] Exporting ACLs"
"$KAFKA_HOME"/bin/kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --list > "$BACKUP_DIR/acls.txt" 2>&1 \
  && echo "[OK] ACLs exported" || echo "[WARN] ACL export failed (maybe no authorizer)"   # ACL

echo "[INFO] Exporting client quotas and SCRAM users"
"$KAFKA_HOME"/bin/kafka-configs.sh --bootstrap-server "$BOOTSTRAP" --describe --entity-type users > "$BACKUP_DIR/users.txt" 2>&1 || true   # Quota/SCRAM user
"$KAFKA_HOME"/bin/kafka-configs.sh --bootstrap-server "$BOOTSTRAP" --describe --entity-type clients > "$BACKUP_DIR/clients.txt" 2>&1 || true

echo "[INFO] Exporting consumer group offsets"
"$KAFKA_HOME"/bin/kafka-consumer-groups.sh --bootstrap-server "$BOOTSTRAP" --describe --all-groups > "$BACKUP_DIR/consumer-groups.txt" 2>&1 \
  && echo "[OK] Consumer groups exported" || echo "[WARN] Consumer group export failed"   # Offset của consumer group

echo "[INFO] Recording end offsets of all partitions"
"$KAFKA_HOME"/bin/kafka-get-offsets.sh --bootstrap-server "$BOOTSTRAP" --time -1 | sort > "$BACKUP_DIR/end-offsets-before.txt" \
  && echo "[OK] End offsets saved" || echo "[ERROR] End offsets export failed"   # -1 = latest; dùng để so sánh sau nâng cấp

echo "[DONE] Backup finished: $BACKUP_DIR"
```

Sao chép thư mục backup sang nơi lưu trữ ngoài server (NAS/object storage) trước khi tiếp tục.

---

## 6. Phase 2 – Chuẩn hóa trên Kafka 3.9.2 (rolling)

Mục tiêu: Java 17 + `inter.broker.protocol.version=3.9` trên cả 3 broker. Kafka 3.9.2 chạy tốt trên Java 17, nên nâng Java ngay bước này để Phase 8 chỉ còn đổi binary.

### 6.1. Rolling restart từng broker (lặp lại cho kafka01 → kafka02 → kafka03)

1. Cài JDK 17 (bản đã vá, mục 1.3) cạnh JDK hiện tại.
2. Sửa `server.properties`: đảm bảo có `inter.broker.protocol.version=3.9`. Nếu muốn, xóa `log.message.format.version` (cấu hình này bị gỡ ở 4.0).
3. Trỏ `JAVA_HOME` của unit `kafka.service` sang JDK 17 (và thêm `Environment="KAFKA_OPTS=-XX:-UseBASE64Intrinsics"` nếu chưa có JDK đã vá).
4. `systemctl restart kafka` **một broker**, rồi chờ ISR đầy đủ (script `health_check.sh` bên dưới) trước khi sang broker kế tiếp.

> Nếu IBP đã là 3.9 sẵn và JDK đã là 17, có thể bỏ qua Phase này.

### 6.2. Script chờ cluster khỏe – `health_check.sh`

Dùng lặp lại sau **mỗi lần restart** ở mọi phase.

```bash
#!/usr/bin/env bash
# Chờ đến khi cluster không còn under-replicated / offline partition
set -u

KAFKA_HOME="/opt/kafka"
BOOTSTRAP="${1:-kafka01:9092,kafka02:9092,kafka03:9092}"
TIMEOUT="${2:-900}"     # Thời gian chờ tối đa (giây)
INTERVAL=10

echo "[INFO] Waiting for cluster to be healthy (timeout ${TIMEOUT}s)"
ELAPSED=0
while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
  URP=$("$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe --under-replicated-partitions 2>/dev/null)
  UNAV=$("$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe --unavailable-partitions 2>/dev/null)
  if [ -z "$URP" ] && [ -z "$UNAV" ]; then
    echo "[OK] No under-replicated or unavailable partitions"
    echo "[DONE] Cluster is healthy"
    exit 0
  fi
  echo "[WARN] Not healthy yet, retry in ${INTERVAL}s (elapsed ${ELAPSED}s)"   # Chưa khỏe, chờ tiếp
  sleep "$INTERVAL"
  ELAPSED=$((ELAPSED + INTERVAL))
done

echo "[ERROR] Cluster did not become healthy within ${TIMEOUT}s"
exit 1
```

---

## 7. Phase 3 – Dựng KRaft controller quorum (Kafka 3.9.2)

> Dùng **cùng binary 3.9.2** cho controller ở giai đoạn migration. Mỗi server chạy thêm 1 process controller (port `9093`) bên cạnh broker (port `9092`).

### 7.1. Lấy cluster ID hiện tại

```bash
/opt/kafka/bin/zookeeper-shell.sh kafka01:2181 get /cluster/id
# Kết quả dạng: {"version":"1","id":"AbCdEfGhIjKlMnOpQrStUv"}
```

Gán vào biến: `CLUSTER_ID=AbCdEfGhIjKlMnOpQrStUv` (controller **phải** dùng đúng cluster ID này).

### 7.2. Tạo `controller.properties` (trên cả 3 server)

Đường dẫn: `/opt/kafka/config/controller.properties`. Chỉ khác nhau ở `node.id` (3001 / 3002 / 3003).

```properties
# --- KRaft controller phục vụ migration ---
process.roles=controller
node.id=3001                       # kafka02 dùng 3002, kafka03 dùng 3003

# Static quorum: liệt kê đủ 3 controller
controller.quorum.voters=3001@kafka01:9093,3002@kafka02:9093,3003@kafka03:9093
controller.listener.names=CONTROLLER
listeners=CONTROLLER://:9093

# Map protocol (nếu broker dùng SSL/SASL thì đổi PLAINTEXT tương ứng)
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
# Listener mà controller dùng để gửi RPC xuống broker (khớp listener inter-broker của broker)
inter.broker.listener.name=PLAINTEXT

# Thư mục metadata của controller (KHÁC thư mục dữ liệu broker)
log.dirs=/data/kafka-controller

# --- Bật migration + kết nối ZooKeeper ---
zookeeper.metadata.migration.enable=true
zookeeper.connect=kafka01:2181,kafka02:2181,kafka03:2181
# Nếu ZK có chroot, thêm /chroot vào cuối zookeeper.connect giống y hệt cấu hình broker
```

Nếu ZooKeeper dùng SASL/TLS, bổ sung các tham số `zookeeper.ssl.*` / JAAS giống cấu hình broker hiện tại.

### 7.3. Format và khởi động controller

```bash
# Chạy trên từng server (user kafka)
mkdir -p /data/kafka-controller && chown kafka:kafka /data/kafka-controller

# Format lần đầu bằng đúng cluster id lấy từ ZooKeeper (static quorum: không dùng --standalone)
sudo -u kafka /opt/kafka/bin/kafka-storage.sh format -t "$CLUSTER_ID" -c /opt/kafka/config/controller.properties
```

Unit systemd `/etc/systemd/system/kafka-controller.service`:

```ini
[Unit]
Description=Apache Kafka KRaft Controller
After=network.target

[Service]
Type=simple
User=kafka
Group=kafka
Environment="JAVA_HOME=/usr/lib/jvm/java-17"
Environment="KAFKA_HEAP_OPTS=-Xms1g -Xmx1g"
Environment="KAFKA_OPTS=-XX:-UseBASE64Intrinsics"
ExecStart=/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/controller.properties
ExecStop=/opt/kafka/bin/kafka-server-stop.sh
Restart=on-failure
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now kafka-controller   # Khởi động lần lượt trên cả 3 server
```

> Bật log chi tiết cho migration trên controller (file log4j của controller, bản 3.9 dùng `log4j.properties`):
> `log4j.logger.org.apache.kafka.metadata.migration=TRACE`

### 7.4. Kiểm tra quorum

```bash
/opt/kafka/bin/kafka-metadata-quorum.sh --bootstrap-controller kafka01:9093 describe --status
```

Kỳ vọng: có `LeaderId` (một trong 3001–3003), `CurrentVoters` đủ 3 phần tử. Lúc này migration **chưa bắt đầu** vì chưa có broker nào ở migration mode.

> **Lưu ý ZK:** nếu từng chạy `zookeeper-security-migration`, xóa node `/migration` hỏng bằng `zookeeper-shell.sh kafka01:2181 delete /migration` (KAFKA-19480) trước khi chuyển sang Phase 4.

---

## 8. Phase 4 – Đưa broker vào migration mode (rolling)

### 8.1. Cấu hình bổ sung cho mỗi broker

Thêm vào `server.properties` (giữ nguyên toàn bộ cấu hình cũ, **chưa** xóa `zookeeper.connect`, **chưa** đổi `broker.id`):

```properties
# --- Thêm cho migration ---
inter.broker.protocol.version=3.9
zookeeper.metadata.migration.enable=true

controller.quorum.voters=3001@kafka01:9093,3002@kafka02:9093,3003@kafka03:9093
controller.listener.names=CONTROLLER
# Phải bổ sung CONTROLLER vào map (giữ các listener cũ)
listener.security.protocol.map=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT

# broker.id phải là số nguyên không âm cố định (không để auto-generate)
broker.id=1
```

Kiểm tra `broker.id` không vượt `reserved.broker.max.id`.

### 8.2. Thực hiện

Với từng broker (kafka01 → kafka02 → kafka03):

1. Sửa `server.properties` như trên.
2. `systemctl restart kafka`.
3. Chạy `health_check.sh` và chờ `[DONE] Cluster is healthy` rồi mới sang broker kế tiếp.

Khi **broker cuối cùng** restart xong, migration **tự động bắt đầu**. Theo dõi log của controller đang active (`/opt/kafka/logs/server.log` hoặc theo cấu hình log của bạn):

```
Completed migration of metadata from Zookeeper to KRaft
```

Đến đây cluster ở **hybrid phase**: controller KRaft điều khiển, broker vẫn ở ZK mode, KRaft controller ghi đồng thời xuống ZK (dual-write).

### 8.3. Kiểm tra sau bước này

```bash
/opt/kafka/bin/kafka-metadata-quorum.sh --bootstrap-controller kafka01:9093 describe --status
/opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka01:9092 --describe | head -n 20
/opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server kafka01:9092 --list
```

Chạy thử produce/consume vào một topic test để xác nhận hoạt động bình thường (xem Phase 11).

> **Đây là điểm quay lui được** – xem mục 13.

---

## 9. Phase 5 – Chuyển từng broker sang KRaft mode (rolling)

Mỗi broker: đổi `broker.id` → `node.id` **cùng giá trị**, thêm `process.roles=broker`, xóa cấu hình ZK/migration/IBP.

### 9.1. `server.properties` của broker KRaft (3.9.2) – ví dụ kafka01

```properties
process.roles=broker
node.id=1                          # GIỮ NGUYÊN giá trị broker.id cũ (kafka02=2, kafka03=3)

controller.quorum.voters=3001@kafka01:9093,3002@kafka02:9093,3003@kafka03:9093
controller.listener.names=CONTROLLER

listeners=PLAINTEXT://:9092
advertised.listeners=PLAINTEXT://kafka01:9092
listener.security.protocol.map=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT

log.dirs=/data/kafka               # GIỮ NGUYÊN thư mục dữ liệu cũ

# Giữ nguyên các cấu hình khác (num.partitions, retention, default.replication.factor, ...)

# --- XÓA các dòng sau ---
# broker.id=1
# zookeeper.connect=...
# zookeeper.metadata.migration.enable=true
# inter.broker.protocol.version=3.9      (KRaft dùng metadata.version)
# control.plane.listener.name=...        (nếu có)
```

Nếu đang dùng ACL với `kafka.security.authorizer.AclAuthorizer`, đổi sang:

```properties
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
```

(ACL đã được migration copy sang KRaft; `super.users` giữ nguyên.)

### 9.2. Thực hiện

Lần lượt từng broker: sửa file → `systemctl restart kafka` → `health_check.sh` → sang broker tiếp theo.

- Broker khởi động lại sẽ tự đọc `meta.properties` có sẵn trong `/data/kafka` – **không format lại**.
- Nếu gặp lỗi `Node ID mismatch` / `cluster id mismatch`: kiểm tra `node.id` trùng `broker.id` cũ và thư mục `log.dirs` đúng.

### 9.3. Kiểm tra

Khi cả 3 broker đã ở KRaft (cluster ở **dual-write phase**):

```bash
/opt/kafka/bin/kafka-metadata-quorum.sh --bootstrap-server kafka01:9092 describe --status
/opt/kafka/bin/kafka-metadata-quorum.sh --bootstrap-server kafka01:9092 describe --replication
```

Kỳ vọng: 3 voter (3001–3003) lag thấp; 3 observer (broker 1, 2, 3).

---

## 10. Phase 6 – Finalize migration và dừng ZooKeeper

> Chỉ thực hiện khi: tất cả broker đã ở KRaft, ứng dụng chạy ổn, đã kiểm tra ít nhất vài giờ (nhiều đơn vị chờ 1–2 tuần). **Sau bước này không thể quay lại ZooKeeper.**

### 10.1. Gỡ cấu hình migration trên controller (rolling từng controller)

Sửa `controller.properties`:

```properties
process.roles=controller
node.id=3001
controller.quorum.voters=3001@kafka01:9093,3002@kafka02:9093,3003@kafka03:9093
controller.listener.names=CONTROLLER
listeners=CONTROLLER://:9093
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
log.dirs=/data/kafka-controller

# --- XÓA ---
# zookeeper.metadata.migration.enable=true
# zookeeper.connect=...
# inter.broker.listener.name=PLAINTEXT   (có thể giữ lại, không ảnh hưởng)
```

Restart **từng controller một** (`systemctl restart kafka-controller`), sau mỗi lần chạy:

```bash
/opt/kafka/bin/kafka-metadata-quorum.sh --bootstrap-controller kafka01:9093 describe --status
```

Chờ quorum có leader và đủ voter rồi mới restart controller tiếp theo. Restart controller đang là leader **sau cùng** để giảm số lần bầu lại.

### 10.2. Dừng ZooKeeper

```bash
# Trên cả 3 server
systemctl stop zookeeper
systemctl disable zookeeper
```

Giữ lại bản backup ZK (Phase 1) và thư mục dữ liệu ZK trong thời gian soak, không xóa ngay.

Cập nhật hệ thống giám sát: bỏ giám sát ZooKeeper, thêm giám sát process controller (mục 12).

---

## 11. Phase 7 & 8 – Soak và nâng cấp lên Kafka 4.4.0

### 11.1. Soak

Chạy cluster KRaft 3.9.2 một thời gian (khuyến nghị vài ngày đến 1–2 tuần) để xác nhận ổn định trước khi lên 4.4.0. Nếu có sự cố trong soak, xử lý trên nền 3.9.2 quen thuộc, tách bạch với rủi ro của lần đổi phiên bản.

### 11.2. Điều kiện trước khi nâng cấp binary (đọc kỹ)

Các thay đổi đáng chú ý từ 4.0 → 4.4 có thể ảnh hưởng cấu hình/công cụ của bạn:

| Hạng mục | Hành động |
|---|---|
| **Java** | Broker/controller/tools cần **Java 17+**. Client tối thiểu Java 11. |
| **Logging** | Chuyển từ Log4j 1.x sang **Log4j2**. File `log4j.properties` cũ không còn dùng; dùng `config/log4j2.yaml` đi kèm, hoặc chuyển đổi bằng `log4j-transform-cli`. |
| **Thư mục config** | `config/kraft/*` đã gộp vào `config/`. Dùng file config riêng của bạn (đường dẫn tuyệt đối) nên ít bị ảnh hưởng. |
| **Cấu hình bị gỡ** | Xóa `log.message.format.version`, `message.format.version`, `offsets.commit.required.acks`, `log.message.timestamp.difference.max.ms` (thay bằng `log.message.timestamp.before.max.ms` / `after.max.ms`), `delegation.token.master.key` (thay `delegation.token.secret.key`). |
| **Mặc định thay đổi** | `log.segment.bytes` tối thiểu 1 MB; `num.recovery.threads.per.data.dir` mặc định 2; `message.timestamp.after.max.ms` mặc định 1 giờ (message có timestamp tương lai > 1 giờ bị từ chối khi dùng CreateTime); `linger.ms` producer mặc định 5. |
| **`broker.id`** | Bị đánh dấu deprecated ở 4.4 (KIP-1232) – bạn đã dùng `node.id`. |
| **Công cụ CLI** | `--bootstrap-server` chỉ nhận dạng `host1:port1,host2:port2` (phân tách bằng dấu phẩy). `kafka-acls.sh` bỏ `--authorizer*`. `kafka-broker-api-versions.sh` deprecated ở 4.4 → dùng `kafka-cluster.sh api-versions`. Các script `--zk-*` không còn. |
| **OAUTHBEARER** | Nếu dùng JWKS endpoint, 4.4 bắt buộc đặt `sasl.oauthbearer.expected.audience` và `sasl.oauthbearer.expected.issuer`, nếu không broker không khởi động. |
| **Consumer rebalance (KIP-848)** | Được bật khi finalize 4.0+. Sau khi consumer group dùng giao thức mới, chỉ downgrade được về 3.4.1+. |
| **Metrics/JMX** | Một số metric group coordinator dạng Yammer deprecated ở 4.4 (KIP-1301) – cập nhật dashboard dần. |
| **Tiered storage / Streams / Connect** | Nếu dùng, đọc thêm mục "Notable changes" trong tài liệu nâng cấp chính thức 4.4. |

### 11.3. Cài binary 4.4.0 (làm sẵn trên cả 3 server, chưa chuyển symlink)

```bash
cd /opt
tar xzf /tmp/kafka_2.13-4.4.0.tgz
chown -R kafka:kafka /opt/kafka_2.13-4.4.0
# Chưa đổi symlink /opt/kafka ở bước này
```

Chuẩn bị bản sao cấu hình cho 4.4.0 (sao chép từ cấu hình đang chạy rồi chỉnh theo bảng 11.2):

```bash
mkdir -p /opt/kafka-conf-4.4
cp /opt/kafka/config/server.properties     /opt/kafka-conf-4.4/server.properties
cp /opt/kafka/config/controller.properties /opt/kafka-conf-4.4/controller.properties
cp /opt/kafka_2.13-4.4.0/config/log4j2.yaml /opt/kafka-conf-4.4/log4j2.yaml
```

Thêm vào unit systemd (cả broker và controller) biến trỏ file log4j2 nếu dùng bản tùy chỉnh:

```ini
Environment="KAFKA_LOG4J_OPTS=-Dlog4j2.configurationFile=file:/opt/kafka-conf-4.4/log4j2.yaml"
```

### 11.4. Thứ tự nâng cấp rolling

**Quy tắc:** nâng **controller trước, broker sau**; từng node một; luôn chờ cluster khỏe trước khi sang node tiếp theo.

Thứ tự đề xuất cho mỗi server (kafka01 → kafka02 → kafka03):

1. Dừng controller trên server đó, nâng binary controller, khởi động lại.
2. Kiểm tra quorum (`kafka-metadata-quorum.sh describe --status`).
3. Sau khi **cả 3 controller** đã ở 4.4.0 → bắt đầu broker.
4. Với broker: dừng, nâng binary, khởi động, chạy `health_check.sh`.

> Controller và broker dùng chung đường dẫn binary `/opt/kafka`. Vì vậy trên mỗi server, nếu dùng symlink dùng chung, hãy đổi symlink **sau khi dừng cả controller lẫn broker** hoặc cho mỗi process một biến `KAFKA_HOME` riêng. Cách đơn giản và an toàn: trỏ `ExecStart` của từng unit trực tiếp vào `/opt/kafka_2.13-4.4.0/bin/kafka-server-start.sh` khi đến lượt, thay vì đổi symlink chung.

#### 11.4.1. Nâng controller (làm xong cả 3 trước)

Trên từng server, lần lượt:

```bash
# 1) Dừng controller
systemctl stop kafka-controller

# 2) Sửa unit: ExecStart trỏ binary 4.4.0 + file cấu hình 4.4
#    ExecStart=/opt/kafka_2.13-4.4.0/bin/kafka-server-start.sh /opt/kafka-conf-4.4/controller.properties
systemctl daemon-reload

# 3) Khởi động lại
systemctl start kafka-controller

# 4) Kiểm tra quorum
/opt/kafka_2.13-4.4.0/bin/kafka-metadata-quorum.sh --bootstrap-controller kafka01:9093 describe --status
```

Không chạy `kafka-storage.sh format` – thư mục controller đã format từ trước. Chờ voter đủ 3 và lag thấp trước khi sang controller kế tiếp.

#### 11.4.2. Nâng broker

Trên từng server, lần lượt:

```bash
# 1) Dừng broker (controlled shutdown tự chuyển leader sang broker khác)
systemctl stop kafka

# 2) Sửa unit: ExecStart trỏ binary 4.4.0 + file cấu hình 4.4
#    ExecStart=/opt/kafka_2.13-4.4.0/bin/kafka-server-start.sh /opt/kafka-conf-4.4/server.properties
systemctl daemon-reload

# 3) Khởi động
systemctl start kafka

# 4) Chờ cluster khỏe rồi mới sang broker kế tiếp
./health_check.sh kafka01:9092,kafka02:9092,kafka03:9092
```

Cấu hình broker 4.4.0 (`server.properties`) – cơ bản giống bản 3.9.2 KRaft đã chuẩn hóa ở mục 9.1, sau khi gỡ các cấu hình bị loại (mục 11.2). Ví dụ:

```properties
process.roles=broker
node.id=1
controller.quorum.voters=3001@kafka01:9093,3002@kafka02:9093,3003@kafka03:9093
controller.listener.names=CONTROLLER
listeners=PLAINTEXT://:9092
advertised.listeners=PLAINTEXT://kafka01:9092
listener.security.protocol.map=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT
log.dirs=/data/kafka
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer   # chỉ khi dùng ACL
```

### 11.5. Kiểm tra trước khi finalize

```bash
# Phiên bản broker thực tế
/opt/kafka_2.13-4.4.0/bin/kafka-cluster.sh api-versions --bootstrap-server kafka01:9092 | head -n 5

# Feature hiện tại (metadata.version vẫn là 3.9-IV0 cho đến khi finalize)
/opt/kafka_2.13-4.4.0/bin/kafka-features.sh --bootstrap-server kafka01:9092 describe
```

Theo dõi vài giờ đến vài ngày: latency, consumer lag, log lỗi. **Trước khi finalize vẫn có thể rollback binary về 3.9.2** (mục 13).

---

## 12. Phase 9 – Finalize 4.4 và giám sát

### 12.1. Finalize

> Cluster metadata **không downgrade được** sau bước này (4.4 có thay đổi metadata).

```bash
/opt/kafka_2.13-4.4.0/bin/kafka-features.sh --bootstrap-server kafka01:9092 upgrade --release-version 4.4

# Kiểm tra lại
/opt/kafka_2.13-4.4.0/bin/kafka-features.sh --bootstrap-server kafka01:9092 describe
```

Kỳ vọng: `metadata.version` đạt `4.4-IV…` mới nhất; các feature như `group.version`, `transaction.version`, `eligible.leader.replicas.version` được nâng theo bản phát hành. Dùng `--dry-run`/`--validate-only` nếu bạn muốn xem trước (kiểm tra tùy chọn của tool bằng `--help`).

Sau finalize, kiểm tra `kraft.version`:

```bash
/opt/kafka_2.13-4.4.0/bin/kafka-features.sh --bootstrap-controller kafka01:9093 describe | grep -E "kraft.version|metadata.version"
```

- Nếu `kraft.version` = `1` (quorum chuyển sang dynamic): **bắt buộc** làm bước Phase 10 để đổi cấu hình `controller.quorum.voters` → `controller.quorum.bootstrap.servers` trên mọi node.
- Nếu `kraft.version` = `0` (vẫn static): cluster hoạt động bình thường, Phase 10 là tùy chọn.

### 12.2. Giám sát sau nâng cấp

Cập nhật dashboard/alert cho mô hình KRaft:

- Giám sát **cả 2 loại process**: broker (9092) và controller (9093) trên từng server.
- `ActiveControllerCount` – tổng trên các controller phải bằng **1**.
- `kafka-metadata-quorum.sh describe --status`: `MaxFollowerLag`, `CurrentVoters` đủ 3.
- `UnderReplicatedPartitions`, `OfflinePartitionsCount`, `IsrShrinksPerSec` trên broker.
- Dung lượng ổ `/data/kafka-controller` (metadata log nhỏ nhưng phải đảm bảo còn chỗ).
- Bỏ các alert ZooKeeper.

---

## 13. Phase 10 (tùy chọn) – Static quorum → Dynamic quorum

Từ Kafka 4.1, cluster có thể chuyển static controller quorum sang dynamic (KIP-853) để thêm/bớt controller mà không phải restart toàn bộ.

1. Kiểm tra: `kafka-features.sh --bootstrap-controller kafka01:9093 describe` – xem `kraft.version`.
2. Nếu đang là `0` và muốn nâng:

```bash
/opt/kafka_2.13-4.4.0/bin/kafka-features.sh --bootstrap-server kafka01:9092 upgrade --feature kraft.version=1
```

3. Sau khi `kraft.version` ≥ 1, trên **tất cả** controller và broker: xóa `controller.quorum.voters`, thêm

```properties
controller.quorum.bootstrap.servers=kafka01:9093,kafka02:9093,kafka03:9093
```

rồi rolling restart (controller trước, broker sau), kiểm tra bằng `describe --status` sau mỗi node.

Khi đã là dynamic quorum, thêm/bớt controller dùng `kafka-metadata-quorum.sh add-controller` / `remove-controller`. Từ 4.4 có thêm `kafka-cluster.sh unregister-controller` (KIP-1312, cần metadata `4.4-IV2`).

---

## 14. Kiểm tra dữ liệu được giữ nguyên

### 14.1. Script so sánh offset – `03_verify_after.sh`

```bash
#!/usr/bin/env bash
# So sánh end offset trước và sau nâng cấp để xác nhận dữ liệu không mất
set -u

KAFKA_HOME="/opt/kafka_2.13-4.4.0"
BOOTSTRAP="kafka01:9092,kafka02:9092,kafka03:9092"
BEFORE_FILE="${1:?Usage: $0 <end-offsets-before.txt>}"
AFTER_FILE="/tmp/end-offsets-after.txt"

echo "[INFO] Collecting current end offsets"
"$KAFKA_HOME"/bin/kafka-get-offsets.sh --bootstrap-server "$BOOTSTRAP" --time -1 | sort > "$AFTER_FILE" \
  || { echo "[ERROR] Cannot collect offsets"; exit 1; }

echo "[INFO] Comparing with $BEFORE_FILE"
# Mỗi dòng dạng topic:partition:offset; offset sau phải >= offset trước (có thể lớn hơn do traffic mới)
LOST=0
while IFS=: read -r topic part off_before; do
  off_after=$(grep -E "^${topic}:${part}:" "$AFTER_FILE" | cut -d: -f3)
  if [ -z "$off_after" ]; then
    echo "[ERROR] Missing partition ${topic}-${part}"; LOST=1
  elif [ "$off_after" -lt "$off_before" ]; then
    echo "[ERROR] Offset regressed on ${topic}-${part}: before=${off_before} after=${off_after}"; LOST=1
  fi
done < "$BEFORE_FILE"

if [ "$LOST" -eq 0 ]; then
  echo "[OK] All partitions present and offsets did not regress"
  echo "[DONE] Data verification passed"
else
  echo "[ERROR] Data verification failed"
  exit 1
fi
```

### 14.2. Kiểm tra bổ sung

```bash
# 1) Topic/partition/replica khớp bản backup
/opt/kafka_2.13-4.4.0/bin/kafka-topics.sh --bootstrap-server kafka01:9092 --describe > /tmp/topics-after.txt
diff <(grep -E "^Topic:" /backup/.../topics-describe.txt | awk '{print $2,$4,$6}' | sort) \
     <(grep -E "^Topic:" /tmp/topics-after.txt | awk '{print $2,$4,$6}' | sort)

# 2) Offset consumer group còn nguyên (không bị reset về 0)
/opt/kafka_2.13-4.4.0/bin/kafka-consumer-groups.sh --bootstrap-server kafka01:9092 --describe --all-groups

# 3) ACL còn nguyên
/opt/kafka_2.13-4.4.0/bin/kafka-acls.sh --bootstrap-server kafka01:9092 --list

# 4) Test produce/consume
echo "[INFO] smoke test" | /opt/kafka_2.13-4.4.0/bin/kafka-console-producer.sh --bootstrap-server kafka01:9092 --topic upgrade-smoke-test
/opt/kafka_2.13-4.4.0/bin/kafka-console-consumer.sh --bootstrap-server kafka01:9092 --topic upgrade-smoke-test --from-beginning --max-messages 1
```

(Tạo topic `upgrade-smoke-test` trước bằng `kafka-topics.sh --create --replication-factor 3 --partitions 3`.)

Chạy kiểm tra này **sau Phase 4, Phase 5, Phase 6 và Phase 9** để phát hiện sớm sự cố.

---

## 15. Kế hoạch quay lui (rollback)

| Đang ở bước | Cách quay lui | Mất dữ liệu? |
|---|---|---|
| Phase 3 (mới dựng controller) | Dừng và xóa 3 controller, xóa `/data/kafka-controller`. | Không |
| Phase 4 (broker ở migration mode, chưa chuyển KRaft) | Dừng controller KRaft; trên ZK so sánh `get /controller_epoch` với `kraft_controller_epoch` trong `get /migration` – nếu epoch KRaft lớn hơn thì `set /controller_epoch` lên giá trị cao hơn; `delete /controller`; `get /migration` rồi `delete /migration`; trên mỗi broker bỏ `zookeeper.metadata.migration.enable`, `controller.listener.names`, `controller.quorum.voters`, rolling restart. Làm nhanh để cluster không thiếu controller lâu. | Không |
| Phase 5 (một phần/toàn bộ broker đã KRaft, **chưa finalize**) | Mỗi broker: bỏ `process.roles`, đổi `node.id` → `broker.id`, khôi phục `zookeeper.connect`, **giữ** `zookeeper.metadata.migration.enable=true`, rolling restart lần 1; dừng controller; xử lý epoch/xóa `/controller` và `/migration` như trên; rolling restart lần 2 bỏ các cấu hình migration. | Không |
| Phase 6 (đã finalize migration) | **Không thể về ZooKeeper.** Chỉ có thể khôi phục từ backup (kịch bản thảm họa, mất dữ liệu sau thời điểm backup). | Có thể |
| Phase 8 (đã nâng binary 4.4.0, **chưa** chạy `upgrade --release-version 4.4`) | Rolling downgrade binary về 3.9.2: broker trước rồi controller (ngược thứ tự nâng cấp), dùng lại cấu hình 3.9.2 đã lưu. `metadata.version` vẫn là 3.9 nên hợp lệ. | Không |
| Phase 9 (đã finalize 4.4) | Metadata không downgrade được. Chỉ xử lý tiến (fix forward) hoặc khôi phục từ backup. | Có thể |

Luôn giữ nguyên thư mục `/opt/kafka_2.13-3.9.2` và bản cấu hình cũ cho đến khi hoàn tất soak sau Phase 9.

---

## 16. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| Migration không bắt đầu sau khi restart broker cuối | Còn broker chưa có `zookeeper.metadata.migration.enable=true`; quorum controller chưa có leader; node `/migration` hỏng (KAFKA-19480) | Kiểm tra từng broker/controller; xem log controller (TRACE `org.apache.kafka.metadata.migration`); xóa `/migration` nếu bị hỏng do công cụ security migration. |
| Controller không khởi động: "cluster id mismatch" | Format controller với cluster id khác ZK | Xóa `/data/kafka-controller`, format lại bằng đúng ID từ `get /cluster/id`. |
| Broker báo lỗi không kết nối được controller | Thiếu `CONTROLLER` trong `listener.security.protocol.map`; firewall chặn 9093 | Bổ sung map; mở port 9093 giữa 3 server. |
| Broker KRaft không khởi động: node id không khớp | `node.id` khác `broker.id` cũ trong `meta.properties` | Đặt `node.id` đúng bằng giá trị cũ, giữ `log.dirs`. |
| `broker.id` / `node.id` trùng controller | Đặt controller trùng ID broker | Controller dùng 3001–3003; không trùng 1–3. |
| Authorization lỗi sau khi sang KRaft | Vẫn dùng `AclAuthorizer` | Đổi sang `StandardAuthorizer`. |
| Broker 4.4 không khởi động với log4j | Cấu hình Log4j 1.x cũ | Dùng `log4j2.yaml`. |
| Broker 4.4 báo lỗi cấu hình không hợp lệ | Còn cấu hình đã bị gỡ (mục 11.2) | Xóa cấu hình đó khỏi `server.properties`. |
| Client cũ không kết nối được 4.4 | Client < 2.1 hoặc thư viện bên thứ ba dùng API cũ | Nâng client; xem KIP-896. |

---

## 17. Checklist thực hiện (in ra để tick)

**Chuẩn bị**
- [ ] Chạy `00_precheck.sh`, mọi mục `[OK]`
- [ ] Chạy `01_backup.sh` trên 3 server, copy backup ra ngoài
- [ ] Có JDK 17 đã vá, binary Kafka 3.9.2 và 4.4.0 trên 3 server
- [ ] Thông báo cửa sổ bảo trì

**Giai đoạn A – ZK → KRaft (Kafka 3.9.2)**
- [ ] Phase 2: Java 17 + IBP 3.9, rolling restart xong
- [ ] Phase 3: 3 controller chạy, quorum OK
- [ ] Phase 4: broker vào migration mode, log "Completed migration of metadata from Zookeeper to KRaft"
- [ ] Phase 5: 3 broker chuyển KRaft, `node.id` giữ nguyên
- [ ] Kiểm tra dữ liệu, ACL, consumer group, produce/consume
- [ ] Phase 6: gỡ migration trên controller, dừng ZooKeeper
- [ ] Soak

**Giai đoạn B – 3.9.2 → 4.4.0**
- [ ] Rà soát cấu hình bị gỡ/đổi (mục 11.2), chuyển Log4j2
- [ ] Nâng 3 controller, kiểm tra quorum
- [ ] Nâng 3 broker, `health_check.sh` sau từng broker
- [ ] Soak, kiểm tra dữ liệu bằng `03_verify_after.sh`
- [ ] `kafka-features.sh upgrade --release-version 4.4`
- [ ] Kiểm tra `kraft.version`, làm Phase 10 nếu cần
- [ ] Cập nhật giám sát, tài liệu vận hành
- [ ] Sau thời gian soak cuối: dọn dẹp binary cũ, dữ liệu ZooKeeper

---

## 18. Tài liệu tham khảo

- Upgrading (Kafka 4.4): https://kafka.apache.org/44/getting-started/upgrade/
- KRaft operations (4.4): https://kafka.apache.org/44/operations/kraft/
- ZooKeeper to KRaft Migration (3.9): https://kafka.apache.org/39/operations/kraft/#zookeeper-to-kraft-migration
- Apache Kafka 4.4.0 Release Announcement: https://kafka.apache.org/blog/2026/10/22/apache-kafka-4.4.0-release-announcement/
- Java4Shell (CVE-2026-114938): https://kafka.apache.org/blog/2026/11/19/mitigating-cve-2026-114938-java4shell-in-apache-kafka-deployments/

> Lưu ý: mọi tham số (đường dẫn, hostname, port, protocol bảo mật) trong tài liệu là giá trị mẫu. Hãy diễn tập toàn bộ quy trình trên một cluster thử nghiệm có cấu hình giống production trước khi thực hiện thật.
