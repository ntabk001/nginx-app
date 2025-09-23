# Cài đặt ELK Cluster trên RHEL bằng Tarball với TLS

## Chuẩn bị hệ thống (Tất cả node)

1. **Cập nhật hệ thống**:
   ```bash
   sudo dnf update -y
   sudo reboot
   ```

2. **Cài đặt Java** (Elasticsearch yêu cầu OpenJDK 17+):
   ```bash
   sudo dnf install java-17-openjdk -y
   ```

3. **Tạo user elasticsearch** (không chạy root):
   ```bash
   sudo useradd -m elasticsearch
   sudo passwd elasticsearch  # Đặt mật khẩu
   ```

4. **Cấu hình /etc/hosts** để resolve tên node (thêm vào file `/etc/hosts`):
   ```plaintext
   192.168.1.101 node1.example.com node1
   192.168.1.102 node2.example.com node2
   192.168.1.103 node3.example.com node3
   ```
   Thay `example.com` bằng domain thực tế.

5. **Tăng giới hạn hệ thống**:
   - Thêm vào `/etc/security/limits.conf`:
     ```plaintext
     elasticsearch - nofile 65536
     elasticsearch - memlock unlimited
     ```
   - Thêm vào `/etc/sysctl.conf`:
     ```plaintext
     vm.max_map_count = 262144
     ```
   - Áp dụng: `sudo sysctl -p`.

## Cài đặt Elasticsearch Cluster với TLS

Thực hiện trên **tất cả node** (node1, node2, node3).

1. **Tải và giải nén Elasticsearch**:
   ```bash
   wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.14.0-linux-x86_64.tar.gz
   tar -xzf elasticsearch-8.14.0-linux-x86_64.tar.gz
   sudo mv elasticsearch-8.14.0 /usr/share/elasticsearch
   sudo chown -R elasticsearch:elasticsearch /usr/share/elasticsearch
   ```

2. **Cấu hình Elasticsearch**:
   - Tạo thư mục cho certs:
     ```bash
     sudo mkdir /etc/elasticsearch/certs
     sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch
     ```
   - Chỉnh sửa `/usr/share/elasticsearch/config/elasticsearch.yml`:
     - Trên **node1** (master-eligible):
       ```yaml
       cluster.name: elk-cluster
       node.name: node1
       node.roles: [master, data, ingest]
       network.host: 192.168.1.101
       discovery.seed_hosts: ["node1", "node2", "node3"]
       cluster.initial_master_nodes: ["node1"]
       http.port: 9200
       xpack.security.enabled: true
       xpack.security.transport.ssl.enabled: true
       xpack.security.transport.ssl.verification_mode: certificate
       xpack.security.transport.ssl.keystore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       xpack.security.transport.ssl.truststore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       xpack.security.http.ssl.enabled: true
       xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       xpack.security.http.ssl.truststore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       ```
     - Trên **node2** và **node3** (data nodes):
       ```yaml
       cluster.name: elk-cluster
       node.name: node2  # hoặc node3
       node.roles: [data, ingest]
       network.host: 192.168.1.102  # hoặc 103
       discovery.seed_hosts: ["node1", "node2", "node3"]
       cluster.initial_master_nodes: ["node1"]
       http.port: 9200
       xpack.security.enabled: true
       xpack.security.transport.ssl.enabled: true
       xpack.security.transport.ssl.verification_mode: certificate
       xpack.security.transport.ssl.keystore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       xpack.security.transport.ssl.truststore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       xpack.security.http.ssl.enabled: true
       xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       xpack.security.http.ssl.truststore.path: /etc/elasticsearch/certs/elastic-certificates.p12
       ```

3. **Tạo TLS Certificates** (chạy trên **node1**):
   ```bash
   sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --out /etc/elasticsearch/certs/elastic-stack-ca.zip
   sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /etc/elasticsearch/certs/elastic-stack-ca.p12 --name node1 --dns node1.example.com --ip 192.168.1.101 --pem --out /etc/elasticsearch/certs/node1.zip
   ```
   - Lặp lại lệnh certutil cho node2 (IP 192.168.1.102) và node3 (IP 192.168.1.103).
   - Giải nén zip và di chuyển file (ca.crt, node1.crt, node1.key) vào `/etc/elasticsearch/certs/`.
   - Tạo keystore password:
     ```bash
     sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore create
     sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password
     ```
   - Copy certs sang node2/node3:
     ```bash
     scp -r /etc/elasticsearch/certs/* user@node2:/etc/elasticsearch/certs/
     scp -r /etc/elasticsearch/certs/* user@node3:/etc/elasticsearch/certs/
     ```

4. **Khởi động Elasticsearch**:
   ```bash
   sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch -d
   ```
   - Kiểm tra: `curl --cacert /etc/elasticsearch/certs/ca.crt -u elastic https://localhost:9200`.
   - Lấy mật khẩu elastic tự động từ log `/usr/share/elasticsearch/logs/elk-cluster.log`.

5. **Set password cho users** (chạy trên node1):
   ```bash
   sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
   ```
   Lưu passwords cho elastic, kibana_system, logstash_system.

## Cài đặt Kibana với TLS

Cài trên **node1**.

1. **Tải và giải nén Kibana**:
   ```bash
   wget https://artifacts.elastic.co/downloads/kibana/kibana-8.14.0-linux-x86_64.tar.gz
   tar -xzf kibana-8.14.0-linux-x86_64.tar.gz
   sudo mv kibana-8.14.0 /usr/share/kibana
   sudo chown -R elasticsearch:elasticsearch /usr/share/kibana
   ```

2. **Cấu hình Kibana**:
   - Chỉnh sửa `/usr/share/kibana/config/kibana.yml`:
     ```yaml
     server.port: 5601
     server.host: "0.0.0.0"
     elasticsearch.hosts: ["https://node1.example.com:9200"]
     elasticsearch.ssl.certificateAuthorities: ["/etc/elasticsearch/certs/ca.crt"]
     elasticsearch.username: "kibana_system"
     elasticsearch.password: "<kibana_password>"
     xpack.security.enabled: true
     xpack.security.http.ssl.enabled: true
     xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/node1.crt
     xpack.security.http.ssl.key: /etc/elasticsearch/certs/node1.key
     ```

3. **Copy certs**:
   ```bash
   sudo mkdir /etc/kibana/certs
   sudo cp /etc/elasticsearch/certs/ca.crt /etc/kibana/certs/
   sudo cp /etc/elasticsearch/certs/node1.crt /etc/kibana/certs/
   sudo cp /etc/elasticsearch/certs/node1.key /etc/kibana/certs/
   sudo chown -R elasticsearch:elasticsearch /etc/kibana
   ```

4. **Khởi động Kibana**:
   ```bash
   sudo -u elasticsearch /usr/share/kibana/bin/kibana &
   ```
   Truy cập https://node1.example.com:5601 (chấp nhận self-signed cert), login elastic/<password>.

## Cài đặt Logstash với TLS

Cài trên **node1**.

1. **Tải và giải nén Logstash**:
   ```bash
   wget https://artifacts.elastic.co/downloads/logstash/logstash-8.14.0-linux-x86_64.tar.gz
   tar -xzf logstash-8.14.0-linux-x86_64.tar.gz
   sudo mv logstash-8.14.0 /usr/share/logstash
   sudo chown -R elasticsearch:elasticsearch /usr/share/logstash
   ```

2. **Cấu hình Logstash**:
   - Tạo pipeline `/usr/share/logstash/config/logstash.conf`:
     ```conf
     input {
       beats {
         port => 5044
         ssl => true
         ssl_certificate => "/etc/elasticsearch/certs/node1.crt"
         ssl_key => "/etc/elasticsearch/certs/node1.key"
       }
     }
     filter {
       # Xử lý log nếu cần
     }
     output {
       elasticsearch {
         hosts => ["https://node1.example.com:9200"]
         ssl => true
         ssl_certificate_verification => true
         cacert => "/etc/elasticsearch/certs/ca.crt"
         user => "logstash_system"
         password => "<logstash_password>"
         index => "logstash-%{+YYYY.MM.dd}"
       }
     }
     ```

3. **Copy certs**:
   ```bash
   sudo mkdir /etc/logstash/certs
   sudo cp /etc/elasticsearch/certs/ca.crt /etc/logstash/certs/
   sudo cp /etc/elasticsearch/certs/node1.crt /etc/logstash/certs/
   sudo cp /etc/elasticsearch/certs/node1.key /etc/logstash/certs/
   sudo chown -R elasticsearch:elasticsearch /etc/logstash
   ```

4. **Khởi động Logstash**:
   ```bash
   sudo -u elasticsearch /usr/share/logstash/bin/logstash -f /usr/share/logstash/config/logstash.conf &
   ```

## Kiểm tra và Test

- **Kiểm tra cluster health**:
  ```bash
  curl --cacert /etc/elasticsearch/certs/ca.crt -u elastic https://node1:9200/_cat/health?v
  ```
  Nên thấy status `green`.

- **Trong Kibana**: Tạo index pattern (Discover > Create index pattern).
- **Test gửi log**: Cài Filebeat trên client, cấu hình output đến Logstash port 5044 với TLS.

**Xử lý lỗi**:
- Kiểm tra log `/usr/share/elasticsearch/logs/elk-cluster.log`, `/usr/share/kibana/logs/kibana.log`, `/usr/share/logstash/logs/logstash-plain.log`.
- Nếu cert lỗi, kiểm tra DNS/IP trong certs. Tham khảo [Elastic Docs](https://www.elastic.co/guide/en/elasticsearch/reference/current/ssl-tls.html).
- Để sản xuất, dùng certs từ CA thực (như Let's Encrypt).