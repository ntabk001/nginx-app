Đã tổng hợp tài liệu đầy đủ về cách **Start/Stop Elastic Agent** trên hệ điều hành RHEL (thuộc nhóm Linux sử dụng systemd). Tôi đã cập nhật nội dung này vào quy trình tổng thể bên dưới.

---

# Tài liệu tổng hợp: Cài đặt và quản lý Elastic Agent để thu thập log Java trên RHEL

## A. Quy trình cài đặt Elastic Agent & Fleet Server

### 1. Chuẩn bị trên Kibana (Fleet UI)

Trước khi cài đặt trên server, bạn cần tạo cấu hình trên Kibana:

1.  **Tạo Agent Policy**: Vào **Management → Fleet → Agent policies** → **Create agent policy**. Đặt tên (ví dụ: `java-log-policy`) và bỏ chọn "Collect system logs" nếu không cần .
2.  **Thêm Fleet Server Integration**: Trong policy vừa tạo, vào tab **Integrations** → **Add integration** → chọn **Fleet Server** → cấu hình và lưu.
3.  **Thêm Custom Logs Integration**:
    *   Vẫn trong policy đó, **Add integration** → chọn **Custom Logs**.
    *   **Log file path**: Nhập đường dẫn log của ứng dụng Java (ví dụ: `/opt/your-app/logs/*.log`).
    *   **Dataset name**: Đặt tên dataset (ví dụ: `javalog`). Chỉ số này sẽ tạo index `logs-javalog-*` trong Elasticsearch.
    *   Lưu integration và áp dụng policy.

### 2. Cài đặt Elastic Agent trên RHEL (Server)

Trên máy chủ RHEL, thực hiện các bước sau:

**Bước 1: Tải và giải nén**
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.x.x-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.x.x-linux-x86_64.tar.gz
cd elastic-agent-8.x.x-linux-x86_64
```

**Bước 2: Enroll Agent vào Fleet**

Bạn cần lấy lệnh `install` từ giao diện Kibana (Fleet → Agents → Add agent). Lệnh sẽ có dạng:
```bash
sudo ./elastic-agent install \
  --url=https://your-fleet-server:8220 \
  --enrollment-token=<your-token>
```

Lưu ý quan trọng: Lệnh này vừa enroll agent vừa cài đặt agent như một service systemd, đảm bảo agent tự động khởi động cùng hệ thống .

## B. Quản lý Elastic Agent (Start/Stop/Restart)

Sau khi cài đặt, Elastic Agent chạy như một service systemd. Bạn có thể quản lý bằng các lệnh chuẩn `systemctl` .

> ⚠️ **Lưu ý quan trọng về bảo mật**: Elastic Agent có cơ chế tự bảo vệ. Kể cả khi dừng service, một số tiến trình có thể vẫn chạy để bảo vệ endpoint. Nếu cần dừng hoàn toàn, hãy đảm bảo bạn có đủ quyền (root) và dùng đúng lệnh .

### 1. Khởi động Elastic Agent
Khi agent đã được cài đặt dưới dạng service (bằng lệnh `install` ở trên), bạn dùng `systemctl` để khởi động :

```bash
sudo systemctl start elastic-agent
```

Nếu hệ thống không dùng systemd (rất hiếm trên RHEL), dùng lệnh cũ:
```bash
sudo service elastic-agent start
```

### 2. Dừng Elastic Agent
Để tạm dừng việc thu thập và gửi dữ liệu, dừng service :

```bash
sudo systemctl stop elastic-agent
```

Lệnh này sẽ chấm dứt tiến trình `elastic-agent` và các tiến trình con (Beats). Agent sẽ không tự động khởi động lại ngay, nhưng **sẽ tự động chạy lại nếu hệ thống khởi động lại** .

### 3. Khởi động lại Elastic Agent
Dùng lệnh `restart` để khởi động lại service :

```bash
sudo systemctl restart elastic-agent
```

### 4. Kiểm tra trạng thái
Để xác nhận agent đang chạy hay dừng :

```bash
sudo systemctl status elastic-agent
```

Đầu ra sẽ hiển thị `active (running)` hoặc `inactive (dead)`.

### 5. Gỡ cài đặt hoàn toàn
Nếu cần gỡ bỏ agent khỏi server :

```bash
sudo elastic-agent uninstall
```

Lệnh này sẽ xóa service và các file cấu hình.

## C. Tổng kết luồng dữ liệu & Kiểm tra

1.  **App Java** ghi log vào file (`/path/to/log/*.log`).
2.  **Elastic Agent** (chạy service systemd) đọc log từ file nhờ cấu hình **Custom Logs Integration** và gửi lên **Elasticsearch**.
3.  **Kibana**: Dữ liệu hiển thị tại **Discover** hoặc **Observability → Logs**. Filter theo data stream `logs-<dataset_name>-*` để xem log.

## D. Xử lý sự cố thường gặp

- **Không thấy log trên Kibana**: Kiểm tra trạng thái agent (`systemctl status elastic-agent`). Kiểm tra đường dẫn file log trong cấu hình Custom Logs có chính xác không.
- **Cần tạm dừng gửi log để bảo trì**: Dùng `sudo systemctl stop elastic-agent`. Khi bảo trì xong, dùng `sudo systemctl start elastic-agent` để tiếp tục.
- **Agent không tự động chạy sau reboot**: Kiểm tra lại cài đặt service (lệnh `install` sẽ tự động cấu hình). Dùng `sudo systemctl enable elastic-agent` để đảm bảo.
- **Không thể dừng agent dù đã dùng lệnh stop**: Agent có thể đang chạy ở chế độ tự bảo vệ. Tham khảo thêm tài liệu về **endpoint self-protection** của Elastic.
