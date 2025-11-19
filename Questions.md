| Tính năng       | Instance Store                     | EBS (Elastic Block Store)           | EFS (Elastic File System)           |
|-----------------|-----------------------------------|-------------------------------------|-------------------------------------|
| **Loại lưu trữ**| Lưu trữ tạm thời (ephemeral)     | Lưu trữ lâu dài (persistent)       | Lưu trữ phân tán (file storage)    |
| **Tình trạng dữ liệu** | Dữ liệu bị mất khi tắt máy      | Dữ liệu còn giữ lại khi tắt máy    | Dữ liệu còn giữ lại khi tắt máy     |
| **Khả năng truy cập** | Chỉ khả dụng cho các instance cụ thể | Với các instance khác nhau          | Được truy cập từ nhiều instance      |
| **Tốc độ**      | Tốc độ truy cập nhanh hơn          | Tốc độ truy cập vừa phải            | Tốc độ thấp hơn so với EBS          |
| **Quy mô**      | Khó mở rộng                         | Có thể mở rộng dễ dàng               | Tự động mở rộng                      |
| **Chia sẻ**     | Không thể chia sẻ giữa các instance| Không thể chia sẻ giữa các instance | Có thể chia sẻ giữa nhiều instance   |
| **Chi phí**     | Không có chi phí cơ bản            | Chi phí phụ thuộc vào dung lượng    | Chi phí phụ thuộc vào dung lượng sử dụng|
| **Sao lưu**     | Không hỗ trợ                       | Hỗ trợ sao lưu snapshot             | Hỗ trợ các tính năng sao lưu         |
| **Thích hợp**   | Ứng dụng tạm thời, Lưu trữ cache  | Ứng dụng yêu cầu lưu trữ lâu dài    | Ứng dụng cần chia sẻ tệp tin        |

### So sánh các Mô hình Định giá Amazon EC2

| Đặc điểm | On-Demand | Savings Plans | Reserved Instances (RIs) | Spot Instances |
| :--- | :--- | :--- | :--- | :--- |
| **Khái niệm** | Trả theo giờ hoặc giây sử dụng, không cam kết. | Cam kết sử dụng một lượng tính toán (theo giờ hoặc $) trong 1 hoặc 3 năm để được giảm giá. | Đặt trước tài nguyên (Instance) trong 1 hoặc 3 năm để được giảm giá đáng kể. | Sử dụng lượng điện toán dư thừa của AWS với giá rẻ nhất, nhưng có thể bị thu hồi bất cứ lúc nào. |
| **Chi phí** | Cao nhất | Tiết kiệm đáng kể so với On-Demand (lên đến ~72%). | Tiết kiệm cao nhất so với On-Demand (lên đến ~72%). | Rẻ nhất (có thể giảm tới 90% so với On-Demand). |
| **Cam kết** | Không cần cam kết. | Cam kết về chi tiêu ($) hoặc sử dụng (giờ). | Cam kết về instance cụ thể (type, region, OS...). | Không cam kết. |
| **Sự linh hoạt** | Linh hoạt nhất. Chạy và dừng bất cứ lúc nào. | Linh hoạt: Giảm giá tự động áp dụng cho bất kỳ instance nào phù hợp, bất kể region, size, OS. | **Kém linh hoạt**: Gắn với instance type, region, platform cụ thể. Có thể đổi (nhưng phức tạp). | **Rất kém linh hoạt**: Instance có thể bị AWS thu hồi với cảnh báo 2 phút. |
| **Phù hợp** | - Workload không thể dự đoán, thay đổi đột ngột.<br>- Ứng dụng mới, đang thử nghiệm.<br>- Workload chạy ngắn hạn. | - Workload ổn định, chạy liên tục.<br>- Môi trường có sự kết hợp của EC2, Fargate, Lambda.<br>- Muốn giảm chi phí mà vẫn giữ sự linh hoạt. | - Workload ổn định, có thể dự đoán.<br>- Ứng dụng database, website luôn chạy.<br>- Có nhu cầu dành riêng tài nguyên (Capacity Reservation). | - Workload có khả năng chịu lỗi, xử lý gián đoạn.<br>- Batch processing, containerized workloads.<br>- Big Data, ML training, rendering.<br>- Workload có thể kiểm tra điểm (checkpoint). |
| **Rủi ro chính** | Chi phí cao nếu chạy instance liên tục. | Nếu không sử dụng hết mức cam kết, vẫn phải trả tiền. | Nếu nhu cầu thay đổi, khó có thể hủy bỏ hoặc chuyển đổi mà không mất phí. | Instance có thể bị chấm dứt bất ngờ, gây gián đoạn dịch vụ. |

---

### Bảng Tóm tắt Bổ sung: Dedicated Hosts & Capacity Reservations

| Đặc điểm | Dedicated Hosts | Capacity Reservations |
| :--- | :--- | :--- |
| **Khái niệm** | Máy chủ vật lý dành riêng cho bạn. Toàn quyền kiểm soát vị trí đặt instance. | Đảm bảo sẵn có capacity (công suất) trong một AZ cụ thể khi bạn cần. |
| **Chi phí** | Đắt nhất (trả cho cả host). Có thể dùng kết hợp với RIs/SP để giảm chi phí. | Trả phí On-Demand cho capacity được đặt trước, dù bạn có chạy instance hay không. |
| **Cam kết** | Mua theo On-Demand, hoặc mua Reserved (1/3 năm). | Không có cam kết dài hạn (theo giờ), nhưng phải trả tiền khi reserve. |
| **Sự linh hoạt** | Mang lại sự linh hoạt trong việc triển khai các license phần mềm (theo socket, core). | Linh hoạt: Bạn có thể tạo/xóa instance trong reservation mà không mất phí reservation. |
| **Phù hợp** | - Cần tuân thủ các quy định về licensing (Microsoft SQL, Windows Server, etc.).<br>- Có yêu cầu tuân thủ nghiêm ngặt (compliance). | - Workload cực kỳ quan trọng, cần đảm bảo capacity tại một thời điểm cụ thể.<br>- Ứng dụng không thể chấp nhận rủi ro hết capacity. |
| **Rủi ro chính** | Chi phí rất cao và quản lý phức tạp. | Chi phí cao vì phải trả tiền ngay cả khi không sử dụng. |

### Lời khuyên Chiến lược

1.  **Tối ưu hóa cơ bản:** Sử dụng kết hợp các mô hình.
    *   **Nền tảng (Baseline):** Dùng **Savings Plans** hoặc **Reserved Instances** cho các workload chạy liên tục, ổn định (như server database, web server).
    *   **Biến động (Variable):** Dùng **On-Demand** cho các phần ứng dụng có lượng truy cập biến động không thể dự đoán.
    *   **Xử lý nền (Background):** Dùng **Spot Instances** cho các tác vụ xử lý batch, xếp hàng, hoặc xử lý dữ liệu có khả năng chịu lỗi.

2.  **Xu hướng:** **Savings Plans** (đặc biệt là Compute Savings Plans) đang trở nên phổ biến hơn Reserved Instances vì sự linh hoạt vượt trội của nó (tự động áp dụng cho instance type và region).

3.  **Luôn phân tích:** Sử dụng công cụ **AWS Cost Explorer** và các khuyến nghị về Reserved Instances/Savings Plans để đưa ra quyết định mua hàng dựa trên dữ liệu sử dụng thực tế của bạn.
Chắc chắn rồi. Dưới đây là bảng so sánh chi tiết giữa 4 dịch vụ Load Balancer của AWS, bao gồm cả Elastic Load Balancer (ELB) - là tên gọi chung cho cả nhóm.

### Bảng So Sánh Các Loại Load Balancer Trên AWS

| Đặc Điểm | **Gateway Load Balancer (GWLB)** | **Network Load Balancer (NLB)** | **Application Load Balancer (ALB)** | **Ghi Chú về Elastic Load Balancer (ELB)** |
| :--- | :--- | :--- | :--- | :--- |
| **Lớp OSI Hoạt Động** | **Lớp 3 & 4** (Network & Transport) | **Lớp 4** (Transport) | **Lớp 7** (Application) | **ELB** là tên gọi chung cho cả 3 dịch vụ: ALB, NLB, GWLB. Trước đây có **Classic Load Balancer (CLB)** - thế hệ cũ, hoạt động ở cả Lớp 4 & 7 nhưng kém linh hoạt hơn. |
| **Loại Lưu Lượng** | **IP Packets** (Giao thức mạng: TCP, UDP,..) | **TCP, UDP, TLS** | **HTTP, HTTPS, gRPC, WebSocket** | |
| **Địa chỉ IP** | **Private IP** (trong VPC) | **Static IP/ Elastic IP** (có thể gán cố định) | **DNS Name** (IP thay đổi) | ALB không hỗ trợ IP tĩnh, trong khi NLB thì có. |
| **Hiệu Suất & Độ Trễ** | **Cực cao**, được tối ưu cho việc chuyển tiếp gói tin. | **Cực thấp** (millisecond), xử lý hàng triệu request/s. | **Thấp**, nhưng cao hơn so với CLB. Tối ưu cho các ứng dụng web. | GWLB & NLB được thiết kế cho các tác vụ đòi hỏi hiệu năng tối đa. |
| **Tính Năng Chính** | **Triển khai & Mở rộng** các thiết bị ảo (Virtual Appliances) như firewall, IDS/IPS. | **Chịu tải cực lớn**, IP tĩnh, chuyển tiếp kết nối mà không can thiệp vào gói tin. | **Định tuyến thông minh** dựa trên nội dung request (Path, Host, Header,...). | GWLB là lựa chọn duy nhất để tích hợp hạ tầng bảo mật một cách linh hoạt. |
| **Sticky Session** | Không hỗ trợ | Không hỗ trợ (dựa trên flow) | **Có hỗ trợ** (dựa trên cookie) | Quan trọng cho các ứng dụng cần giữ phiên người dùng trên cùng một máy chủ. |
| **SSL/TLS Offloading** | Không (thường do appliance xử lý) | **Passthrough** (chuyển tiếp SSL đến target) | **Có** (giải mã tại ALB) | ALB giúp giảm tải xử lý SSL cho các máy chủ phía sau. |
| **Health Checks** | TCP, HTTP | TCP, HTTP, HTTPS | HTTP, HTTPS | Tất cả đều hỗ trợ health check để đảm bảo chỉ định tuyến đến các target khỏe mạnh. |
| **Target Types** | **IP Address** (chủ yếu) | **Instance, IP, ALB** | **Instance, IP, Lambda, Container** | ALB linh hoạt nhất, có thể tích hợp trực tiếp với serverless (Lambda). |
| **Chi Phí** | Tính phí theo **Giờ sử dụng GWLB** và **LCU** (Load Balancer Capacity Units). | Tính phí theo **Giờ sử dụng NLB** và **LCU**. | Tính phí theo **Giờ sử dụng ALB** và **LCU**. | Mô hình tính phí tương tự nhau, nhưng LCU được tính dựa trên các yếu tố khác nhau (số kết nối, băng thông,...). |
| **Use Cases Chính** | - **Bảo mật:** Firewall (Palo Alto, Check Point), IDS/IPS.<br>- **Kiểm tra mạng:** Packet brokers. | - **Ứng dụng hiệu năng cực cao** (gaming, trading).<br>- **Cần IP tĩnh.**<br>- Proxy cho TCP/UDP. | - **Ứng dụng web hiện đại** (microservices, container).<br>- **Định tuyến nâng cao** (API Gateway, A/B Testing).<br>- Serverless (Lambda). | Mỗi loại phục vụ một mục đích kiến trúc cụ thể. |

---

### Tóm Tắt & Hướng Dẫn Lựa Chọn

Hãy tưởng tượng bạn đang xây một tòa nhà:

1.  **Application Load Balancer (ALB) - "Người Quản Lý Tòa Nhà Thông Minh"**
    *   **Khi nào dùng:** Khi bạn có một ứng dụng web hoặc API hiện đại (kiến trúc microservices, sử dụng container). ALB đọc hiểu "nội dung" của request (ví dụ: URL path, hostname) để quyết định gửi nó đến dịch vụ nào.
    *   **Ví dụ:** Một request đến `api.example.com/users` được gửi tới nhóm máy chủ User Service, trong khi `api.example.com/orders` được gửi tới nhóm máy chủ Order Service.

2.  **Network Load Balancer (NLB) - "Tổng Đài Viên Tốc Độ"**
    *   **Khi nào dùng:** Khi bạn cần hiệu suất cực cao, độ trễ cực thấp và không cần ALB xử lý các logic phức tạp. NLB hoạt động như một "ống dẫn" cực nhanh, chuyển tiếp lưu lượng dựa trên địa chỉ IP và port.
    *   **Ví dụ:** Ứng dụng giao dịch chứng khoán, game online, hoặc khi bạn cần một địa chỉ IP cố định cho Load Balancer.

3.  **Gateway Load Balancer (GWLB) - "Trạm Kiểm Soát An Ninh"**
    *   **Khi nào dùng:** Khi bạn cần chèn các thiết bị ảo (virtual appliance) vào luồng mạng để kiểm tra, phân tích hoặc bảo mật lưu lượng. GWLB giúp triển khai, quản lý và mở rộng các appliance này một cách dễ dàng.
    *   **Ví dụ:** Triển khai một firewall ảo (như FortiGate trên AWS) để kiểm tra mọi lưu lượng ra/vào VPC của bạn. Mọi gói tin đều phải đi qua "trạm kiểm soát" này.

4.  **Elastic Load Balancer (ELB)**
    *   Đây là **tên dịch vụ tổng thể** của AWS. Khi bạn nói "tôi dùng ELB", có nghĩa là bạn đang dùng một trong ba loại kể trên (ALB, NLB, GWLB). **Classic Load Balancer (CLB)** là thế hệ đầu tiên và nên tránh sử dụng cho các kiến trúc mới, trừ khi có yêu cầu đặc biệt tương thích ngược.

**Lời Khuyên Cuối Cùng:**
*   **Dùng ALB cho hầu hết các ứng dụng web và API.**
*   **Dùng NLB cho các ứng dụng đòi hỏi hiệu năng tối đa hoặc cần IP tĩnh.**
*   **Dùng GWLB khi bạn cần tích hợp các giải pháp bảo mật hoặc kiểm tra mạng của bên thứ ba.**
