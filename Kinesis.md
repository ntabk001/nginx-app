### **Bảng So Sánh AWS Kinesis Streams, Kinesis Data Analytics và Kinesis Data Firehose**

| Tính Năng / Đặc Điểm | **Kinesis Data Streams (KDS)** | **Kinesis Data Firehose (KDF)** | **Kinesis Data Analytics (KDA)** |
| :--- | :--- | :--- | :--- |
| **Vai trò & Mục đích** | **Thu nhận & xử lý dữ liệu theo thời gian thực (real-time).** <br>• Tích luỹ dữ liệu từ nhiều nguồn. <br>• Cho phép nhiều ứng dụng tiêu thụ cùng một luồng dữ liệu. | **Tải & chuyển đổi dữ liệu theo lô (batch) đến đích lưu trữ.** <br>• Tự động vận chuyển dữ liệu đến các kho dữ liệu (S3, Redshift, Elasticsearch). <br>• Không cần viết code để vận chuyển. | **Phân tích dữ liệu stream theo thời gian thực.** <br>• Chạy các truy vấn SQL hoặc ứng dụng Apache Flink để phân tích dữ liệu đang chảy. <br>• Phát hiện anomaly, tạo bảng điều khiển real-time. |
| **Mô hình Xử lý** | **Tự quản lý (Producer -> KDS -> Consumer).** <br>Bạn phải tự viết ứng dụng Consumer (dùng KCL/KPL) để đọc và xử lý dững liệu. | **Fully Managed (Serverless).** <br>Bạn chỉ cần cấu hình đích đến, Firehose tự động thu thập, chuyển đổi (nếu cần) và giao hàng. | **Fully Managed (Serverless).** <br>Bạn cung cấp truy vấn SQL hoặc code Flink, KDA tự động chạy và mở rộng cơ sở hạ tầng. |
| **Khả năng Mở rộng** | **Thủ công hoặc tự động.** <br>• Dựa trên số **Shard**. <br>• Mỗi shard hỗ trợ 1MB/s input và 2MB/s output. Cần lập kế hoạch capacity. | **Tự động (Auto-scaling).** <br>Tự động mở rộng quy mô để xử lý khối lượng dữ liệu đầu vào. Không cần quản lý shard. | **Tự động (Auto-scaling).** <br>Tự động điều chỉnh tài nguyên tính toán dựa trên khối lượng và độ phức tạp của truy vấn. |
| **Độ trễ (Latency)** | **Rất thấp (Hàng giây).** <br>Dữ liệu có sẵn cho consumer ngay sau khi được ghi vào stream. | **Gần thời gian thực (Hàng giây đến vài phút).** <br>Độ trễ phụ thuộc vào kích thước batch (từ 60 giây đến 15 phút). | **Thời gian thực (Hàng giây).** <br>Kết quả phân tích được trả về gần như ngay lập tức. |
| **Độ bền dữ liệu** | **24 giờ đến 365 ngày (mặc định là 24h).** <br>Dữ liệu được lưu giữ trong stream một khoảng thời gian xác định, cho phép xử lý lại (replay). | **Không lưu giữ.** <br>Firehose là một ống dẫn, không phải kho lưu trữ. Nó chuyển dữ liệu đi và không lưu lại. | **Không lưu giữ trực tiếp.** <br>Nó xử lý dữ liệu từ nguồn (KDS/KDF) và gửi kết quả đi. |
| **Nguồn Dữ liệu Đầu vào** | • Ứng dụng custom (SDK) <br>• AWS IoT <br>• CloudWatch Logs <br>• Kinesis Agent | • Kinesis Data Streams <br>• AWS IoT <br>• CloudWatch Logs <br>• Ứng dụng custom (SDK) | • Kinesis Data Streams <br>• Kinesis Data Firehose <br>• Amazon MSK |
| **Đích đến Dữ liệu** | • Ứng dụng Consumer (Lambda, EC2, EKS) <br>• Kinesis Data Firehose <br>• Kinesis Data Analytics | • **Amazon S3** <br>• **Amazon Redshift** <br>• **Amazon Elasticsearch** <br>• **Splunk** <br>• **HTTP Endpoint** <br>• **Datadog** | • **Kinesis Data Streams** <br>• **Kinesis Data Firehose** <br>• **AWS Lambda** |
| **Khả năng Chuyển đổi Dữ liệu** | Không. Bạn phải xử lý trong ứng dụng Consumer. | **Có.** <br>• Tích hợp sẵn với **AWS Lambda** để chuyển đổi dữ liệu trước khi giao hàng. <br>• Định dạng từ JSON sang Parquet/ORC (cho S3). | **Có (Đây là chức năng chính).** <br>• Sử dụng SQL hoặc Flink để lọc, tổng hợp, sắp xếp và làm giàu dữ liệu stream. |
| **Chi phí** | Dựa trên số **Shard** và lượng dữ liệu **PUT**. | Dựa trên lượng **dữ liệu đã xử lý (tính bằng GB)**. | Dựa trên số **KPU (Kinesis Processing Unit)** và thời gian chạy. |
| **Kịch bản sử dụng điển hình** | • Ứng dụng giao dịch tài chính real-time. <br>• Phân tích clickstream trên website. <br>• Giám sát log và sự kiện từ server. | • Tích luỹ log vào S3 để phân tích bằng Athena/EMR. <br>• Tải dữ liệu vào Redshift Data Warehouse. <br>• Index dữ liệu vào Elasticsearch cho tìm kiếm. | • Bảng điều khiển real-time về hiệu suất kinh doanh. <br>• Phát hiện gian lận (fraud detection) theo thời gian thực. <br>• Phân tích và làm sạch dữ liệu IoT trước khi lưu trữ. |

---

### **Tóm tắt và Lựa chọn Dịch vụ**

*   **Khi nào dùng Kinesis Data Streams?**
    *   Khi bạn cần **độ trễ cực thấp** và khả năng **xử lý dữ liệu phức tạp, tùy chỉnh** bằng code của riêng bạn.
    *   Khi bạn cần nhiều ứng dụng **cùng đọc một luồng dữ liệu** (multi-consumer).
    *   Khi bạn cần **lưu giữ dữ liệu tạm thời** để có thể xử lý lại.

*   **Khi nào dùng Kinesis Data Firehose?**
    *   Khi mục tiêu chính của bạn là **tải dữ liệu một cách đáng tin cậy và tự động** đến một kho lưu trữ hoặc dịch vụ phân tích (như S3, Redshift).
    *   Khi bạn muốn một giải pháp **serverless, không phải quản lý server hoặc shard**.
    *   Khi bạn cần chuyển đổi dữ liệu đơn giản (như nén, định dạng lại) trên đường đi.

*   **Khi nào dùng Kinesis Data Analytics?**
    *   Khi bạn cần **phân tích và đưa ra thông tin chi tiết từ dữ liệu stream ngay lập tức**.
    *   Khi bạn muốn sử dụng **SQL** để truy vấn dữ liệu đang chảy, thay vì viết code phức tạp.
    *   Khi bạn cần phát hiện các mẫu (pattern) hoặc sự kiện bất thường (anomaly) trong thời gian thực.

### **Luồng dữ liệu kết hợp phổ biến**

Một kiến trúc phổ biến và mạnh mẽ là kết hợp cả ba dịch vụ:

**Nguồn Dữ liệu (IoT, App Logs) → Kinesis Data Streams → Kinesis Data Analytics → Kinesis Data Firehose → Đích (S3, Redshift)**

*   **KDS** thu thập dữ liệu thô với độ trễ thấp.
*   **KDA** lọc, tổng hợp và làm giàu dữ liệu quan trọng theo thời gian thực.
*   **KDF** lấy kết quả từ KDA và tải một cách đáng tin cậy vào kho lưu trữ cuối cùng.

Hy vọng bảng so sánh này giúp bạn có cái nhìn rõ ràng và đưa ra lựa chọn phù hợp cho dự án của mình!
