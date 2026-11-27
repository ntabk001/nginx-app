# Nâng cấp Kafka 3.9.2 + ZooKeeper 3.9.5 lên Kafka 4.4.0 (KRaft) – giữ nguyên dữ liệu

> Phiên bản tài liệu: v2 – 25/11/2026
> Thay đổi so với v1: ZooKeeper cài riêng tại `/opt/zookeeper` (dùng `zkServer.sh`/`zkCli.sh` của ZK); Kafka được quản lý bằng script `sh` (`kafka-ctl.sh`) thay cho systemd.
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
| ZooKeeper | Cài **riêng** tại `/opt/zookeeper` (`bin/zkServer.sh`, `bin/zkCli.sh`, `conf/zoo.cfg`), port client `2181`, chạy trên 3 server. Mọi thao tác với ZK trong tài liệu dùng `/opt/zookeeper/bin/zkCli.sh` |
| Kafka broker hiện tại | `broker.id` = 1, 2, 3 ; listener `PLAINTEXT://:9092` |
| Thư mục cài Kafka | `/opt/kafka` (hoặc `/opt/kafka_2.13-3.9.2`) |
| Thư mục dữ liệu broker | `/data/kafka` (giữ nguyên, **không xóa, không format**) |
| Thư mục dữ liệu controller (mới) | `/data/kafka-controller` |
| User chạy dịch vụ | `kafka` |
| Quản lý tiến trình | Script `sh` (không dùng systemd): `/opt/kafka-scripts/kafka-ctl.sh` + `kafka-env.sh` (mục 2.1). PID file trong `/opt/kafka-scripts/run`, log console/gc mỗi role tách riêng `/var/log/kafka/broker`, `/var/log/kafka/controller` |
| Node ID controller (mới) | 3001, 3002, 3003 |
| Quorum | **static quorum** (`controller.quorum.voters`) – ổn định nhất cho migration, có thể chuyển sang dynamic ở bước tùy chọn cuối tài liệu |

> Nếu cluster dùng SASL/SSL, thêm các cấu hình listener/security tương ứng vào controller và broker (map `CONTROLLER` sang protocol đang dùng). Phần mẫu dưới đây dùng PLAINTEXT để dễ đọc.

### 2.1. Script start/stop Kafka (thay systemd)

Từ Phase 3 trên **mỗi server sẽ có 2 process Kafka** (broker + controller). Có hai lưu ý khi dùng script tự viết:

1. `kafka-server-stop.sh` của Kafka tìm mọi process `kafka.Kafka` và **kill cả hai** (broker lẫn controller). Vì vậy **không dùng** `kafka-server-stop.sh` từ Phase 3 trở đi; dùng PID file riêng cho từng role như script dưới đây.
2. Hai process không được ghi chung thư mục log (cùng `server.log`). Script đặt `LOG_DIR` riêng cho từng role.

Tạo thư mục và hai file sau trên cả 3 server (chạy bằng user `kafka`):

```bash
mkdir -p /opt/kafka-scripts/run /var/log/kafka/broker /var/log/kafka/controller
chmod 755 /opt/kafka-scripts
```

**`/opt/kafka-scripts/kafka-env.sh`** – biến môi trường dùng chung. Khi nâng phiên bản chỉ cần sửa file này (không cần đổi symlink):

```bash
#!/usr/bin/env bash
# File biến môi trường dùng chung cho kafka-ctl.sh; sửa file này khi đổi phiên bản Kafka

# JDK dùng cho Kafka (Phase 2 đổi sang JDK 17 đã vá)
export JAVA_HOME="/usr/lib/jvm/java-17"

# Binary và cấu hình riêng cho từng role: controller và broker có thể ở phiên bản khác nhau trong lúc rolling upgrade
export BROKER_KAFKA_HOME="/opt/kafka"                      # Giai đoạn B: /opt/kafka_2.13-4.4.0
export BROKER_CONF="/opt/kafka/config/server.properties"   # Giai đoạn B: /opt/kafka-conf-4.4/server.properties
export CONTROLLER_KAFKA_HOME="/opt/kafka"                  # Giai đoạn B: /opt/kafka_2.13-4.4.0
export CONTROLLER_CONF="/opt/kafka/config/controller.properties"   # Giai đoạn B: /opt/kafka-conf-4.4/controller.properties

# Heap theo role
export BROKER_HEAP="-Xms2g -Xmx2g"
export CONTROLLER_HEAP="-Xms1g -Xmx1g"

# Cấu hình log4j riêng theo role; để trống khi dùng bản 3.9.2 (dùng log4j.properties mặc định)
# Giai đoạn B (4.4.0): -Dlog4j2.configurationFile=file:/opt/kafka-conf-4.4/log4j2.yaml
export BROKER_LOG4J_OPTS=""
export CONTROLLER_LOG4J_OPTS=""

# Tuỳ chọn JVM thêm cho mọi process Kafka (Java4Shell workaround); nếu dùng JAAS thì thêm -Djava.security.auth.login.config=... vào đây
export KAFKA_EXTRA_OPTS="-XX:-UseBASE64Intrinsics"

export KAFKA_LOG_DIR_BASE="/var/log/kafka"
export PID_DIR="/opt/kafka/pid"
export STOP_TIMEOUT=300     # Thời gian chờ tối đa (giây) khi dừng; broker cần thời gian controlled shutdown
```

**`/opt/kafka-scripts/kafka-ctl.sh`**:

```bash
#!/usr/bin/env bash
# Script start/stop/restart/status cho Kafka broker và controller (không dùng systemd)
# Usage: kafka-ctl.sh <broker|controller> <start|stop|restart|status>
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/kafka-env.sh"

usage() {
  echo "Usage: $0 <broker|controller> <start|stop|restart|status>"
  exit 1
}

ROLE="${1:-}"
ACTION="${2:-}"
if [ -z "$ROLE" ] || [ -z "$ACTION" ]; then usage; fi

# Chọn binary, cấu hình, heap theo role
case "$ROLE" in
  broker)
    HOME_DIR="$BROKER_KAFKA_HOME"; CONF="$BROKER_CONF"; HEAP="$BROKER_HEAP"; L4J="$BROKER_LOG4J_OPTS" ;;
  controller)
    HOME_DIR="$CONTROLLER_KAFKA_HOME"; CONF="$CONTROLLER_CONF"; HEAP="$CONTROLLER_HEAP"; L4J="$CONTROLLER_LOG4J_OPTS" ;;
  *) usage ;;
esac

PID_FILE="$PID_DIR/kafka.pid"
LOG_DIR_ROLE="$KAFKA_LOG_DIR_BASE/$ROLE"
export PATH="$JAVA_HOME/bin:$PATH"

# Lấy PID đang chạy: kiểm tra PID file và file cấu hình trong command line để tránh nhầm process
get_pid() {
  [ -f "$PID_FILE" ] || return 1
  local pid
  pid="$(cat "$PID_FILE")"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && ps -p "$pid" -o args= | grep -q -- "$CONF"; then
    echo "$pid"
    return 0
  fi
  return 1
}

do_start() {
  local pid
  if pid="$(get_pid)"; then
    echo "[WARN] Kafka $ROLE is already running (pid $pid)"
    return 0
  fi
  [ -f "$CONF" ] || { echo "[ERROR] Config file not found: $CONF"; return 1; }
  [ -x "$HOME_DIR/bin/kafka-server-start.sh" ] || { echo "[ERROR] kafka-server-start.sh not found in $HOME_DIR"; return 1; }
  mkdir -p "$PID_DIR" "$LOG_DIR_ROLE" || { echo "[ERROR] Cannot create run/log directories"; return 1; }

  echo "[INFO] Starting Kafka $ROLE (home: $HOME_DIR, config: $CONF)"
  # Chạy trong subshell để không làm bẩn biến môi trường; kafka-server-start.sh dùng exec nên PID = PID của java
  (
    export LOG_DIR="$LOG_DIR_ROLE"
    export KAFKA_HEAP_OPTS="$HEAP"
    export KAFKA_OPTS="$KAFKA_EXTRA_OPTS ${KAFKA_OPTS:-}"
    if [ -n "$L4J" ]; then export KAFKA_LOG4J_OPTS="$L4J"; else unset KAFKA_LOG4J_OPTS; fi
    nohup "$HOME_DIR/bin/kafka-server-start.sh" "$CONF" > "$LOG_DIR_ROLE/$ROLE.out" 2>&1 &
    echo $! > "$PID_FILE"
  )
  sleep 5
  if pid="$(get_pid)"; then
    echo "[OK] Kafka $ROLE started (pid $pid)"
  else
    echo "[ERROR] Kafka $ROLE exited right after start, check $LOG_DIR_ROLE/$ROLE.out"
    return 1
  fi
}

do_stop() {
  local pid
  if ! pid="$(get_pid)"; then
    echo "[WARN] Kafka $ROLE is not running"
    rm -f "$PID_FILE"
    return 0
  fi
  echo "[INFO] Stopping Kafka $ROLE (pid $pid), timeout ${STOP_TIMEOUT}s"
  kill -TERM "$pid"       # SIGTERM để broker thực hiện controlled shutdown
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$STOP_TIMEOUT" ]; then
      echo "[ERROR] Kafka $ROLE did not stop within ${STOP_TIMEOUT}s; not forcing kill, investigate manually"
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
  rm -f "$PID_FILE"
  echo "[OK] Kafka $ROLE stopped"
}

do_status() {
  local pid
  if pid="$(get_pid)"; then
    echo "[OK] Kafka $ROLE is running (pid $pid)"
  else
    echo "[WARN] Kafka $ROLE is not running"
    return 1
  fi
}

case "$ACTION" in
  start)   do_start ;;
  stop)    do_stop ;;
  restart) do_stop && do_start ;;
  status)  do_status ;;
  *)       usage ;;
esac
```

```bash
chmod 750 /opt/kafka-scripts/kafka-ctl.sh
/opt/kafka-scripts/kafka-ctl.sh broker status
```

Cách chuyển sang script mới cho broker đang chạy (làm ở Phase 2, **trước khi có controller**): dừng broker bằng cách cũ của bạn (script stop hiện tại hoặc `kafka-server-stop.sh`), rồi khởi động lại bằng `kafka-ctl.sh broker start`. Nếu bạn đã có script start riêng chạy ổn, vẫn có thể dùng, miễn đáp ứng hai lưu ý ở đầu mục này.

### 2.2. Tự khởi động khi reboot (không có systemd)

Nếu cần Kafka tự lên sau khi server reboot, thêm vào crontab của user `kafka` (controller lên trước, broker sau):

```bash
@reboot sleep 20 && /opt/kafka-scripts/kafka-ctl.sh controller start >> /var/log/kafka/ctl.log 2>&1 && sleep 30 && /opt/kafka-scripts/kafka-ctl.sh broker start >> /var/log/kafka/ctl.log 2>&1
```

Trong giai đoạn 1 (trước Phase 3) chưa có controller, dòng cron chỉ cần phần `broker start`. ZooKeeper (`/opt/zookeeper`) giữ cách khởi động hiện tại của bạn cho đến khi tắt ở Phase 6.

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
ZK_HOST="kafka01:2181"
ZK_HOME="/opt/zookeeper"                 # ZooKeeper cài riêng
KAFKA_HOME="${KAFKA_HOME:-/opt/kafka}"

echo "[INFO] Checking Java version"
java -version 2>&1 | head -n 1   # In phiên bản Java đang dùng

echo "[INFO] Checking Kafka broker list"
"$KAFKA_HOME"/bin/kafka-broker-api-versions.sh --bootstrap-server "$BOOTSTRAP" 2>/dev/null \
  | grep -E "^[a-zA-Z0-9.-]+:[0-9]+ \(id:" || echo "[WARN] Cannot read broker list"   # Liệt kê broker đang sống

echo "[INFO] Checking ZooKeeper status"
"$ZK_HOME"/bin/zkServer.sh status 2>&1 | tail -n 2   # Kỳ vọng: Mode: leader hoặc follower

echo "[INFO] Reading cluster id from ZooKeeper"
"$ZK_HOME"/bin/zkCli.sh -server "$ZK_HOST" get /cluster/id 2>/dev/null | grep -E '"id"' \
  || echo "[ERROR] Cannot read /cluster/id"   # Lấy cluster id, cần dùng ở Phase 3

echo "[INFO] Checking under-replicated partitions"
URP=$("$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe --under-replicated-partitions 2>/dev/null)
if [ -z "$URP" ]; then echo "[OK] No under-replicated partitions"; else echo "[ERROR] Under-replicated partitions found:"; echo "$URP"; fi

echo "[INFO] Checking unavailable partitions"
UNAV=$("$KAFKA_HOME"/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe --unavailable-partitions 2>/dev/null)
if [ -z "$UNAV" ]; then echo "[OK] No unavailable partitions"; else echo "[ERROR] Unavailable partitions found:"; echo "$UNAV"; fi

echo "[INFO] Checking pending topic deletions in ZooKeeper"
"$ZK_HOME"/bin/zkCli.sh -server "$ZK_HOST" ls /admin/delete_topics 2>/dev/null | tail -n 1   # Kỳ vọng: []

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
| Cấu hình Kafka (`server.properties`, `log4j.properties`, JAAS, keystore...) | Copy thư mục `config` + thư mục script start/stop (`/opt/kafka-scripts` hoặc script hiện có) |
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
ZK_HOME="/opt/zookeeper"           # ZooKeeper cài riêng
ZK_CONF="$ZK_HOME/conf/zoo.cfg"
# Đọc dataDir và dataLogDir từ zoo.cfg
ZK_DATA_DIR="$(grep -E '^dataDir=' "$ZK_CONF" 2>/dev/null | cut -d= -f2)"
ZK_DATALOG_DIR="$(grep -E '^dataLogDir=' "$ZK_CONF" 2>/dev/null | cut -d= -f2)"

mkdir -p "$BACKUP_DIR" || { echo "[ERROR] Cannot create $BACKUP_DIR"; exit 1; }
echo "[INFO] Backup directory: $BACKUP_DIR"

echo "[INFO] Backing up Kafka config"
tar czf "$BACKUP_DIR/kafka-config.tgz" "$CONF_DIR" /opt/kafka-scripts 2>/dev/null \
  && echo "[OK] Kafka config saved" || echo "[WARN] Some config files were not found"   # Cấu hình + script start/stop hiện có

echo "[INFO] Backing up ZooKeeper config and data (dataDir: ${ZK_DATA_DIR:-N/A})"
tar czf "$BACKUP_DIR/zookeeper-data.tgz" "$ZK_CONF" ${ZK_DATA_DIR:+"$ZK_DATA_DIR"} ${ZK_DATALOG_DIR:+"$ZK_DATALOG_DIR"} 2>/dev/null \
  && echo "[OK] ZooKeeper config and data saved" || echo "[WARN] ZooKeeper data not found on this host"   # Cấu hình + dữ liệu ZK

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
3. Đặt `JAVA_HOME` sang JDK 17 trong `kafka-env.sh` (hoặc trong script start hiện tại của bạn) và thêm `-XX:-UseBASE64Intrinsics` vào `KAFKA_EXTRA_OPTS` nếu chưa có JDK đã vá.
4. Dừng và khởi động **một broker**: `/opt/kafka-scripts/kafka-ctl.sh broker restart` (lần đầu chuyển sang script mới, xem cuối mục 2.1), rồi chờ ISR đầy đủ (script `health_check.sh` bên dưới) trước khi sang broker kế tiếp.

> ZooKeeper `/opt/zookeeper` giữ nguyên, **không** cần đổi Java của ZK ở bước này (ZK 3.9.x chạy được trên JDK hiện tại).

> Nếu IBP đã là 3.9 sẵn và JDK đã là 17, có thể bỏ qua Phase này.

### 6.2. Script chờ cluster khỏe – `health_check.sh`

Dùng lặp lại sau **mỗi lần restart** ở mọi phase.

```bash
#!/usr/bin/env bash
# Chờ đến khi cluster không còn under-replicated / offline partition
set -u

KAFKA_HOME="${KAFKA_HOME:-/opt/kafka}"   # Có thể truyền KAFKA_HOME=/opt/kafka_2.13-4.4.0 khi chạy ở Phase 8
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
/opt/zookeeper/bin/zkCli.sh -server kafka01:2181 get /cluster/id
# Kết quả (dòng cuối) dạng: {"version":"1","id":"AbCdEfGhIjKlMnOpQrStUv"}
```

Gán vào biến: `AbCdEfGhIjKlMnOpQrStUv` (controller **phải** dùng đúng cluster ID này). Có thể đối chiếu với `cluster.id` trong `meta.properties` tại `/data/kafka` của broker.

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
mkdir -p /data/kafka-controller

# Format lần đầu bằng đúng cluster id lấy từ ZooKeeper (static quorum: không dùng --standalone)
/opt/kafka/bin/kafka-storage.sh format -t "$CLUSTER_ID" -c /opt/kafka/config/controller.properties
```

Khởi động controller bằng script (lần lượt trên cả 3 server). Từ bước này dùng `kafka-ctl.sh` cho **cả controller lẫn broker**, không dùng `kafka-server-stop.sh` (mục 2.1):

```bash
/opt/kafka-scripts/kafka-ctl.sh controller start
/opt/kafka-scripts/kafka-ctl.sh controller status
tail -n 50 /var/log/kafka/controller/server.log
```

> Nếu dùng broker đã được khởi động bằng cách cũ (chưa có PID file), `kafka-ctl.sh broker status` sẽ báo not running. Hãy chuyển broker sang `kafka-ctl.sh` ở Phase 2 như hướng dẫn cuối mục 2.1.

> Bật log chi tiết cho migration trên controller (file log4j của controller, bản 3.9 dùng `log4j.properties`):
> `log4j.logger.org.apache.kafka.metadata.migration=TRACE`

### 7.4. Kiểm tra quorum

```bash
/opt/kafka/bin/kafka-metadata-quorum.sh --bootstrap-controller kafka01:9093 describe --status
```

Kỳ vọng: có `LeaderId` (một trong 3001–3003), `CurrentVoters` đủ 3 phần tử. Lúc này migration **chưa bắt đầu** vì chưa có broker nào ở migration mode.

> **Lưu ý ZK:** nếu từng chạy `zookeeper-security-migration`, xóa node `/migration` hỏng bằng `/opt/zookeeper/bin/zkCli.sh -server kafka01:2181 delete /migration` (KAFKA-19480) trước khi chuyển sang Phase 4.

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
2. `/opt/kafka-scripts/kafka-ctl.sh broker restart`.
3. Chạy `health_check.sh` và chờ `[DONE] Cluster is healthy` rồi mới sang broker kế tiếp.

Khi **broker cuối cùng** restart xong, migration **tự động bắt đầu**. Theo dõi log của controller đang active (`/var/log/kafka/controller/server.log`):

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

Lần lượt từng broker: sửa file → `/opt/kafka-scripts/kafka-ctl.sh broker restart` → `health_check.sh` → sang broker tiếp theo.

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

Restart **từng controller một** (`/opt/kafka-scripts/kafka-ctl.sh controller restart`), sau mỗi lần chạy:

```bash
/opt/kafka/bin/kafka-metadata-quorum.sh --bootstrap-controller kafka01:9093 describe --status
```

Chờ quorum có leader và đủ voter rồi mới restart controller tiếp theo. Restart controller đang là leader **sau cùng** để giảm số lần bầu lại.

### 10.2. Dừng ZooKeeper
```bash
# Trên cả 3 server: dừng ZooKeeper cài riêng
/opt/zookeeper/bin/zkServer.sh stop
/opt/zookeeper/bin/zkServer.sh status    # Kỳ vọng: không chạy
```

Gỡ ZooKeeper khỏi crontab `@reboot` / script khởi động tự động (nếu có) để nó không tự lên lại sau reboot. Giữ lại bản backup ZK (Phase 1) và thư mục `/opt/zookeeper` cùng dữ liệu `dataDir` trong thời gian soak, không xóa ngay.

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

### 11.3. Cài binary 4.4.0 (làm sẵn trên cả 3 server, chưa đổi kafka-env.sh)
```bash
cd /opt
tar xzf /tmp/kafka_2.13-4.4.0.tgz
chown -R kafka:kafka /opt/kafka_2.13-4.4.0
# Không đổi symlink /opt/kafka; việc chọn phiên bản do kafka-env.sh quyết định cho từng role
```

Chuẩn bị bản sao cấu hình cho 4.4.0 (sao chép từ cấu hình đang chạy rồi chỉnh theo bảng 11.2):

```bash
mkdir -p /opt/kafka-conf-4.4
cp /opt/kafka/config/server.properties      /opt/kafka-conf-4.4/server.properties
cp /opt/kafka/config/controller.properties  /opt/kafka-conf-4.4/controller.properties
cp /opt/kafka_2.13-4.4.0/config/log4j2.yaml /opt/kafka-conf-4.4/log4j2.yaml
```

Trong `kafka-env.sh`, khi đến lượt từng role, đổi các biến sau (không đổi cho role chưa đến lượt):

```bash
# Controller (Phase 11.4.1)
export CONTROLLER_KAFKA_HOME="/opt/kafka_2.13-4.4.0"
export CONTROLLER_CONF="/opt/kafka-conf-4.4/controller.properties"
export CONTROLLER_LOG4J_OPTS="-Dlog4j2.configurationFile=file:/opt/kafka-conf-4.4/log4j2.yaml"

# Broker (Phase 11.4.2)
export BROKER_KAFKA_HOME="/opt/kafka_2.13-4.4.0"
export BROKER_CONF="/opt/kafka-conf-4.4/server.properties"
export BROKER_LOG4J_OPTS="-Dlog4j2.configurationFile=file:/opt/kafka-conf-4.4/log4j2.yaml"
```

> Tách biến theo role là có chủ ý: `KAFKA_LOG4J_OPTS` kiểu Log4j2 **không** được áp cho process còn ở 3.9.2 (nó ghi đè cấu hình log mặc định của 3.9). Script `kafka-ctl.sh` chỉ truyền cờ log4j của đúng role.

### 11.4. Thứ tự nâng cấp rolling
**Quy tắc:** nâng **controller trước, broker sau**; từng node một; luôn chờ cluster khỏe trước khi sang node tiếp theo.

Thứ tự đề xuất (kafka01 → kafka02 → kafka03):

1. Nâng controller trên cả 3 server (mục 11.4.1), kiểm tra quorum sau mỗi node.
2. Sau khi **cả 3 controller** đã ở 4.4.0 → nâng broker từng server (mục 11.4.2).

#### 11.4.1. Nâng controller (làm xong cả 3 trước)

Trên từng server, lần lượt:

```bash
# 1) Dừng controller
/opt/kafka-scripts/kafka-ctl.sh controller stop

# 2) Sửa kafka-env.sh: CONTROLLER_KAFKA_HOME / CONTROLLER_CONF / CONTROLLER_LOG4J_OPTS trỏ sang 4.4.0 (mục 11.3)

# 3) Khởi động lại
/opt/kafka-scripts/kafka-ctl.sh controller start

# 4) Kiểm tra quorum (dùng tool của 4.4.0)
/opt/kafka_2.13-4.4.0/bin/kafka-metadata-quorum.sh --bootstrap-controller kafka01:9093 describe --status
```

Không chạy `kafka-storage.sh format` – thư mục controller đã format từ trước. Chờ voter đủ 3 và lag thấp trước khi sang controller kế tiếp.

#### 11.4.2. Nâng broker

Trên từng server, lần lượt:

```bash
# 1) Dừng broker (SIGTERM -> controlled shutdown tự chuyển leader sang broker khác)
/opt/kafka-scripts/kafka-ctl.sh broker stop

# 2) Sửa kafka-env.sh: BROKER_KAFKA_HOME / BROKER_CONF / BROKER_LOG4J_OPTS trỏ sang 4.4.0 (mục 11.3)

# 3) Khởi động
/opt/kafka-scripts/kafka-ctl.sh broker start

# 4) Chờ cluster khỏe rồi mới sang broker kế tiếp
KAFKA_HOME=/opt/kafka_2.13-4.4.0 ./health_check.sh kafka01:9092,kafka02:9092,kafka03:9092
```

Cấu hình broker 4.4.0 (`/opt/kafka-conf-4.4/server.properties`) – cơ bản giống bản 3.9.2 KRaft đã chuẩn hóa ở mục 9.1, sau khi gỡ các cấu hình bị loại (mục 11.2). Ví dụ:

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

Các lệnh ZooKeeper trong bảng (`get /controller_epoch`, `delete /controller`, `get /migration`, `delete /migration`) chạy bằng `/opt/zookeeper/bin/zkCli.sh -server kafka01:2181 <lệnh>`. Khởi động lại ZooKeeper (nếu đã dừng) bằng `/opt/zookeeper/bin/zkServer.sh start`.

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
- [ ] Đã tạo `/opt/kafka-scripts/kafka-env.sh` và `kafka-ctl.sh` trên 3 server (mục 2.1)
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
