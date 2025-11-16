# Tất tần tật câu lệnh netstat hữu ích

## Giới thiệu

Anh em làm DevOps/system trong công việc hàng ngày, chắc hẳn đã từng gặp tình huống: deploy một ứng dụng web mới lên server, `systemctl start` báo thành công, nhưng khi mở trình duyệt truy cập vào địa chỉ IP thì lại nhận được thông báo "This site can't be reached".

Lúc này, một loạt câu hỏi sẽ hiện ra: Liệu có phải do firewall? Service đã thực sự chạy chưa? Hay port đang bị một ứng dụng khác chiếm dụng?

Để trả lời những câu hỏi này một cách hệ thống, chúng ta cần một công cụ để thấy những gì đang diễn ra bên trong mạng của server. `netstat` chính là công cụ kinh điển và hiệu quả cho công việc này. Có thể nói là cái thứ đầu tiên xuất hiện trong đầu mình khi vấn đề sảy ra luôn, cứ netstat đã tính sau :))

## Netstat là gì?

`netstat` (network statistics) là một tiện ích dòng lệnh có sẵn trên hầu hết các hệ điều hành Linux. Nó cung cấp thông tin chi tiết về các kết nối mạng, bảng định tuyến, thống kê interface, và hơn thế nữa.

Hãy xem nó như một công cụ chẩn đoán, giúp ta thấy được:

- Những port nào đang mở và ở trạng thái lắng nghe (listening)
- Process nào đang sử dụng port đó
- Các kết nối nào đang được thiết lập (established)

## Các lệnh netstat hữu dụng

### 1. Xem các port đang listening

Đây là lệnh bạn sẽ dùng thường xuyên nhất để kiểm tra xem dịch vụ của mình đã chạy và sẵn sàng nhận kết nối hay chưa.

```bash
netstat -tuln
```

**Giải thích:**
- `-t`: Hiển thị các kết nối TCP
- `-u`: Hiển thị các kết nối UDP
- `-l`: Chỉ hiển thị các socket đang ở trạng thái `LISTEN`
- `-n`: Hiển thị địa chỉ IP và số hiệu port (dạng số), không phân giải tên miền. Lệnh sẽ chạy nhanh hơn

### 2. Xác định process đang sử dụng port

Khi cần biết chính xác process nào đang chiếm một port cụ thể, hãy thêm option `-p`.

```bash
netstat -tulpn
```

**Giải thích:**
- `-p`: Hiển thị Process ID (PID) và tên của process sở hữu socket

**Lưu ý:** Bạn cần quyền root hoặc sudo để xem thông tin process của các dịch vụ không thuộc sở hữu của user hiện tại.

### 3. Xem toàn bộ các socket đang hoạt động

Khi bạn muốn có một cái nhìn tổng quan nhất về tất cả hoạt động mạng, bao gồm cả các port đang lắng nghe (`LISTEN`) và các kết nối đã được thiết lập (`ESTABLISHED`), hãy thêm option `-a`.

```bash
netstat -a
```

Lệnh này sẽ liệt kê tất cả các socket TCP, UDP và cả Unix sockets. Nó hữu ích khi bạn muốn rà soát nhanh mọi thứ mà không cần bộ lọc cụ thể.

### 4. Lọc riêng các kết nối TCP

Trong nhiều trường hợp, bạn chỉ quan tâm đến các giao thức hướng kết nối như HTTP, SSH, hoặc FTP, vốn đều sử dụng TCP. Để lọc riêng các kết nối này và làm cho kết quả gọn gàng hơn, hãy dùng lệnh:

```bash
netstat -tn
```

Option `-t` chỉ hiển thị TCP và `-n` giúp hiển thị địa chỉ IP/port thay vì phân giải tên miền.

### 5. Lọc riêng các kết nối UDP

Tương tự, để kiểm tra các dịch vụ sử dụng giao thức không hướng kết nối (connectionless) như DNS, DHCP, hoặc NTP, bạn có thể lọc riêng kết nối UDP bằng option `-u`.

```bash
netstat -un
```

### 6. Kiểm tra bảng định tuyến (Routing Table)

Đây là một lệnh cực kỳ quan trọng để chẩn đoán các vấn đề về kết nối liên mạng (ví dụ: server không thể truy cập Internet). Nó hiển thị route table của kernel, cho bạn biết gói tin sẽ được gửi đi đâu.

```bash
netstat -rn
```

**Kết quả mẫu:**
```
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG        0 0          0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 eth0
```

Kết quả của lệnh này sẽ giúp bạn xác nhận **default gateway** đã được cấu hình đúng hay chưa. Đây là cổng mặc định cho tất cả traffic không có định tuyến cụ thể trong mạng local.

### 7. Xem thống kê chi tiết của các giao thức mạng

Để đi sâu hơn vào việc chẩn đoán, bạn có thể xem các số liệu thống kê cho từng giao thức (IP, TCP, UDP, ICMP) với option `-s`.

```bash
netstat -s
```

Lệnh này sẽ cung cấp các thông tin như:
- Tổng số gói tin đã gửi/nhận
- Số gói tin bị lỗi
- Số lần kết nối được thiết lập
- Số lần retransmission

Rất hữu ích để tìm ra các vấn đề tiềm ẩn về hiệu năng hoặc lỗi đường truyền.

### 8. Xem thông tin các interface mạng

Để xem danh sách các interface mạng (`eth0`, `lo`,…) cùng với thống kê về lưu lượng dữ liệu trên từng interface, bạn có thể dùng option `-i`.

```bash
netstat -i
```

**Kết quả mẫu:**
```
Kernel Interface table
Iface   MTU   RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg
eth0   1500  125432      0      0 0        98234      0      0      0 BMRU
lo    65536   12345      0      0 0        12345      0      0      0 LRU
```

Kết quả sẽ hiển thị các thông số như MTU (Maximum Transmission Unit) và số lượng gói tin nhận (RX) và gửi (TX) thành công hoặc bị lỗi trên mỗi interface.

## Các tình huống áp dụng thực tế

### Kiểm tra dịch vụ SSH

Để đảm bảo server cho phép kết nối SSH, ta kiểm tra port 22:

```bash
netstat -tulpn | grep 22
```

**Kết quả mong đợi:**
```
tcp   0  0 0.0.0.0:22   0.0.0.0:* LISTEN   1234/sshd
```

**Giải thích kết quả:**
- `0.0.0.0:22`: Dịch vụ đang lắng nghe trên port **22** của tất cả các interface mạng
- `LISTEN`: Trạng thái cho thấy dịch vụ đã sẵn sàng nhận kết nối mới
- `1234/sshd`: Process `sshd` với PID là `1234` đang quản lý port này

Nếu bạn không thể SSH vào server, lệnh này sẽ giúp xác nhận liệu dịch vụ SSH có đang chạy hay không.

### Kiểm tra Web Server (HTTP/HTTPS)

Quay lại vấn đề ở đầu bài. Sau khi khởi động Nginx hoặc Apache, hãy dùng lệnh sau để xác thực:

```bash
netstat -tulpn | grep 80
```

**Kết quả mong đợi:**
```
tcp   0  0 0.0.0.0:80   0.0.0.0:* LISTEN   4567/httpd
```

Điều này xác nhận rằng web server của bạn đang hoạt động và lắng nghe trên port 80.

Tiếp theo, khi có người dùng truy cập, bạn có thể kiểm tra các kết nối đã được thiết lập:

```bash
netstat -an | grep 80
```

Bạn sẽ thấy các dòng có trạng thái `ESTABLISHED`, ví dụ:

```
tcp   0  0 192.168.1.10:80   192.168.1.5:50000   ESTABLISHED
```

**Hiểu về trạng thái kết nối:**
- `LISTEN` có thể hiểu là "cửa hàng đã mở cửa"
- `ESTABLISHED` có nghĩa là "đang có khách hàng giao dịch tại quầy"

### Kiểm tra các kết nối đang hoạt động

Để có cái nhìn tổng quan về các kết nối TCP đang hoạt động trên server, sử dụng lệnh:

```bash
netstat -tn
```

Kết quả sẽ liệt kê các kết nối, bao gồm IP nguồn (`Foreign Address`) và IP đích (`Local Address`), giúp bạn biết được ai đang kết nối đến server của mình.

### Kiểm tra Default Gateway

Khi server mất kết nối Internet, một trong những bước đầu tiên là kiểm tra route table:

```bash
netstat -rn
```

Hãy tìm dòng có `Destination` là `0.0.0.0`. Gateway được chỉ định ở dòng này chính là đích đến cho tất cả traffic không có định tuyến cụ thể. Nếu thông tin này sai, server sẽ không thể kết nối ra ngoài mạng local.

## Bổ sung kiến thức nâng cao

### Các trạng thái kết nối TCP

Khi làm việc với `netstat`, bạn sẽ thấy nhiều trạng thái khác nhau của kết nối TCP:

- **LISTEN**: Socket đang chờ kết nối đến
- **ESTABLISHED**: Kết nối đã được thiết lập và đang hoạt động
- **SYN_SENT**: Socket đang cố gắng thiết lập kết nối (đã gửi SYN)
- **SYN_RECEIVED**: Socket đã nhận được yêu cầu kết nối từ mạng
- **FIN_WAIT1**: Socket đã đóng, kết nối đang được đóng
- **FIN_WAIT2**: Kết nối đã đóng, socket đang chờ đóng từ phía remote
- **TIME_WAIT**: Socket đang chờ để đảm bảo remote đã nhận được ACK đóng kết nối
- **CLOSE_WAIT**: Remote đã đóng, đang chờ socket cục bộ đóng
- **LAST_ACK**: Remote đã đóng, socket cục bộ đã đóng, đang chờ ACK
- **CLOSING**: Cả hai socket đang đóng nhưng dữ liệu chưa được gửi hết

### Các lệnh kết hợp hữu ích

**Đếm số lượng kết nối theo trạng thái:**
```bash
netstat -an | awk '/tcp/ {print $6}' | sort | uniq -c
```

**Tìm top 10 IP kết nối nhiều nhất:**
```bash
netstat -tn | tail -n +3 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
```

**Kiểm tra port cụ thể có đang được sử dụng không:**
```bash
netstat -tuln | grep :8080
```

**Xem các kết nối đang ở trạng thái TIME_WAIT:**
```bash
netstat -an | grep TIME_WAIT | wc -l
```

### So sánh netstat với các công cụ thay thế

#### ss (socket statistics)
`ss` là công cụ hiện đại hơn, nhanh hơn và được khuyến nghị thay thế cho `netstat`:

```bash
# Tương đương với netstat -tuln
ss -tuln

# Tương đương với netstat -tulpn
ss -tulpn

# Xem các kết nối established
ss -t state established
```

#### lsof (list open files)
`lsof` có thể dùng để kiểm tra port đang được process nào sử dụng:

```bash
# Xem process đang sử dụng port 80
lsof -i :80

# Xem tất cả kết nối mạng của một process
lsof -p <PID> -a -i
```

### Troubleshooting thường gặp

**Vấn đề 1: Port đã được sử dụng**
```bash
# Tìm process đang chiếm port
netstat -tulpn | grep :80
# Hoặc
lsof -i :80
# Kill process nếu cần
kill -9 <PID>
```

**Vấn đề 2: Quá nhiều kết nối TIME_WAIT**
```bash
# Kiểm tra số lượng
netstat -an | grep TIME_WAIT | wc -l

# Giải pháp: Điều chỉnh kernel parameters trong /etc/sysctl.conf
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
```

**Vấn đề 3: Server không thể kết nối Internet**
```bash
# Kiểm tra default gateway
netstat -rn | grep ^0.0.0.0

# Kiểm tra DNS
netstat -rn | grep 8.8.8.8

# Test kết nối
ping -c 3 8.8.8.8
```

## Lời kết

`netstat` là một công cụ mạnh mẽ và cần thiết trong bộ công cụ của bất kỳ ai làm việc với Linux. Nắm vững các câu lệnh trên sẽ giúp bạn nhanh chóng xác định và xử lý các vấn đề liên quan đến kết nối mạng một cách hiệu quả.

Nếu chưa từng dùng thì bạn hãy dành chút thời gian mở terminal và tự mình kiểm tra xem server đang có những kết nối nào nhé. Thực hành là cách tốt nhất để ghi nhớ các lệnh này!

---

**Tags:** #Linux #Networking #Netstat #DevOps #SystemAdmin #Troubleshooting
