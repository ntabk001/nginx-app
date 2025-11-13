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
