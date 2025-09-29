# Hướng dẫn tăng kích thước PVC trong cụm Kubernetes sử dụng Ceph và ArgoCD

## Tổng quan

Trong cụm Kubernetes sử dụng **Ceph** làm storage backend (thường qua Ceph CSI driver) và ArgoCD để triển khai ứng dụng, việc tăng kích thước Persistent Volume Claim (PVC) yêu cầu quy trình cẩn thận để tránh mất dữ liệu. Tính năng `--cascade=orphan` trong Kubernetes (không phải ArgoCD) được sử dụng khi xóa StatefulSet để giữ lại pod và PVC, đảm bảo dữ liệu không bị xóa. Tính năng "Orphaned Resources Monitoring" của ArgoCD không trực tiếp liên quan đến resize PVC, nhưng có thể gây rủi ro xóa PVC mồ côi nếu không cấu hình đúng.

Quy trình này giả định bạn sử dụng **StatefulSet** với PVC và Ceph làm backend storage (qua Ceph CSI driver, hỗ trợ RBD hoặc CephFS). Để an toàn tối đa, tài liệu ưu tiên sử dụng lệnh `kubectl` thay vì sync qua ArgoCD để tránh nguy cơ xóa PVC do logic prune. Sau khi hoàn tất, bạn cần đồng bộ Git để tuân thủ GitOps.

---

## Các bước kiểm tra và thực hiện (Sử dụng lệnh `kubectl`)

### 1. Sao lưu dữ liệu
- **Mục đích**: Đảm bảo dữ liệu trên PVC được sao lưu để tránh mất mát.
- **Hành động**:
  - Mount PVC và sao lưu thủ công:
    ```bash
    kubectl exec -it <pod-name> -- tar czf /tmp/backup.tar.gz /path/to/data
    ```
  - Hoặc sử dụng tool như Velero (nếu tích hợp với Ceph snapshot).
- **Lưu ý**: Ceph hỗ trợ snapshot qua CSI, bạn có thể tạo snapshot trước:
  ```bash
  kubectl apply -f - <<EOF
  apiVersion: snapshot.storage.k8s.io/v1
  kind: VolumeSnapshot
  metadata:
    name: <pvc-name>-snapshot
  spec:
    volumeSnapshotClassName: <ceph-snapshot-class>
    source:
      persistentVolumeClaimName: <pvc-name>
  EOF
  ```

### 2. Kiểm tra StorageClass hỗ trợ expansion
- **Mục đích**: Xác nhận StorageClass của Ceph (e.g., `ceph-rbd` hoặc `cephfs`) hỗ trợ `allowVolumeExpansion`.
- **Hành động**:
  - Chạy lệnh:
    ```bash
    kubectl get storageclass <storageclass-name> -o yaml | grep allowVolumeExpansion
    ```
    - Kết quả phải là `allowVolumeExpansion: true`. Nếu là `false`, chỉnh sửa:
      ```bash
      kubectl patch storageclass <storageclass-name> -p '{"allowVolumeExpansion": true}'
      ```
  - Kiểm tra Ceph cluster:
    - Đảm bảo Ceph pool (RBD hoặc CephFS) có đủ dung lượng:
      ```bash
      ssh <ceph-admin-node> ceph df
      ```
    - Nếu dùng Ceph RBD, kiểm tra pool quota:
      ```bash
      ssh <ceph-admin-node> rbd pool stats <pool-name>
      ```
- **Lưu ý**: Ceph CSI driver (phiên bản 3.0 trở lên) hỗ trợ volume expansion cho cả RBD và CephFS. Đảm bảo driver được cài đặt và cấu hình đúng.

### 3. Kiểm tra trạng thái PVC
- **Mục đích**: Đảm bảo PVC đang ở trạng thái `Bound` và filesystem hỗ trợ online resize (e.g., ext4, xfs cho CephFS; RBD thường không cần resize filesystem).
- **Hành động**:
  - Xem chi tiết PVC:
    ```bash
    kubectl get pvc <pvc-name> -o yaml
    ```
    - Kiểm tra `status.phase: Bound` và `spec.resources.requests.storage` (kích thước hiện tại).
  - Xem Persistent Volume (PV):
    ```bash
    kubectl describe pv <pv-name>
    ```
    - Xác nhận PV liên kết với Ceph pool đúng (RBD hoặc CephFS).
- **Lưu ý**: Với Ceph RBD, resize thường chỉ cần tăng size volume (không cần resize filesystem). Với CephFS, kiểm tra filesystem trong pod.

### 4. Kiểm tra pod và ứng dụng
- **Mục đích**: Đảm bảo ứng dụng chịu được restart (stateful hay stateless).
- **Hành động**:
  - Kiểm tra pod:
    ```bash
    kubectl get pods -l app=<your-app>
    ```
  - Test scale down/up để xác nhận ứng dụng recover:
    ```bash
    kubectl scale statefulset <statefulset-name> --replicas=0
    kubectl scale statefulset <statefulset-name> --replicas=<original-replicas>
    ```
- **Lưu ý**: Nếu ứng dụng yêu cầu high availability, dùng multiple replicas để giảm downtime.

### 5. Scale StatefulSet về 0
- **Mục đích**: Dừng pod để tránh truy cập dữ liệu trong lúc resize.
- **Hành động**:
  ```bash
  kubectl scale statefulset <statefulset-name> --replicas=0
  ```
- **Kiểm tra**:
  ```bash
  kubectl get pods -l app=<your-app>
  ```
  - Đảm bảo không còn pod nào chạy.

### 6. Xóa StatefulSet với `--cascade=orphan`
- **Mục đích**: Xóa StatefulSet nhưng giữ lại pod và PVC.
- **Hành động**:
  ```bash
  kubectl delete statefulset <statefulset-name> --cascade=orphan
  ```
- **Kiểm tra**:
  ```bash
  kubectl get pvc <pvc-name>
  ```
  - Đảm bảo PVC vẫn tồn tại (trạng thái `Bound` hoặc `Released`).

### 7. Cập nhật manifest và apply trực tiếp
- **Mục đích**: Cập nhật kích thước PVC trong manifest và áp dụng bằng `kubectl` để tránh prune của ArgoCD.
- **Hành động**:
  - Chỉnh sửa file YAML (local hoặc trong Git, nhưng apply bằng `kubectl`):
    ```yaml
    apiVersion: apps/v1
    kind: StatefulSet
    metadata:
      name: <statefulset-name>
    spec:
      ...
      volumeClaimTemplates:
      - metadata:
          name: <pvc-name>
        spec:
          accessModes: ["ReadWriteOnce"]
          storageClassName: <ceph-rbd-or-cephfs>
          resources:
            requests:
              storage: 20Gi  # Tăng từ 10Gi lên 20Gi
    ```
  - Apply manifest:
    ```bash
    kubectl apply -f <manifest-file>.yaml
    ```
- **Lưu ý**: Đảm bảo tên StatefulSet và `volumeClaimTemplates` không đổi để tái sử dụng PVC cũ.

### 8. Scale lên số lượng mong muốn
- **Mục đích**: Khởi động lại pod để mount PVC với kích thước mới.
- **Hành động**:
  ```bash
  kubectl scale statefulset <statefulset-name> --replicas=<original-replicas>
  ```
- **Kiểm tra**:
  ```bash
  kubectl get pods -l app=<your-app>
  ```
  - Đảm bảo pod chạy lại và mount đúng PVC.

### 9. Xác nhận resize
- **Mục đích**: Đảm bảo PVC được resize và filesystem (nếu cần) được cập nhật.
- **Hành động**:
  - Kiểm tra PVC:
    ```bash
    kubectl get pvc <pvc-name>
    ```
    - Xác nhận `status.capacity.storage` là kích thước mới (e.g., `20Gi`).
  - Với CephFS, kiểm tra filesystem trong pod:
    ```bash
    kubectl exec -it <pod-name> -- df -h /path/to/pvc
    ```
    - Nếu filesystem chưa resize:
      ```bash
      kubectl exec -it <pod-name> -- resize2fs /dev/<device>  # ext4
      kubectl exec -it <pod-name> -- xfs_growfs /path/to/pvc  # xfs
      ```
  - Với Ceph RBD, không cần resize filesystem (volume tự động mở rộng).
- **Kiểm tra Ceph backend**:
  - Với RBD:
    ```bash
    ssh <ceph-admin-node> rbd info <pool-name>/<image-name>
    ```
  - Với CephFS:
    ```bash
    ssh <ceph-admin-node> ceph fs status
    ```

### 10. Đồng bộ lại với Git (để tránh drift với ArgoCD)
- **Mục đích**: Cập nhật Git để trạng thái cụm khớp với manifest.
- **Hành động**:
  - Commit file YAML đã chỉnh sửa (từ bước 7) vào Git repository.
  - Trigger sync trên ArgoCD:
    - **GUI**: Vào Application > Sync > Bỏ chọn "Prune Resources" > Chọn "Replace" nếu cần > Sync.
    - **CLI**:
      ```bash
      argocd app sync <app-name> --prune=false
      ```
- **Lưu ý**: Bước này đảm bảo ArgoCD không đánh dấu ứng dụng là "OutOfSync" do apply trực tiếp bằng `kubectl`.

---

## Case sử dụng GUI ArgoCD (Bổ sung)

ArgoCD GUI không hỗ trợ trực tiếp `--cascade=orphan` hoặc scale pod, nên bạn vẫn cần CLI cho các bước này. Tuy nhiên, bạn có thể tối ưu hóa sử dụng GUI cho sync và monitor:

### 1-4. Chuẩn bị
- Backup, kiểm tra StorageClass, PVC, pod: Dùng CLI hoặc Kubernetes Dashboard, vì ArgoCD GUI không hỗ trợ kiểm tra chi tiết Ceph/PVC.

### 5. Cập nhật manifest trong Git
- Chỉnh sửa YAML trong Git với size PVC mới, commit và push.

### 6. Scale xuống và xóa StatefulSet
- **GUI không hỗ trợ**: Dùng CLI cho scale và xóa với orphan:
  ```bash
  kubectl scale statefulset <statefulset-name> --replicas=0
  kubectl delete statefulset <statefulset-name> --cascade=orphan
  ```

### 7. Sync trên GUI
- Vào Application > Sync > Bỏ chọn "Prune Resources" > Chọn "Replace" > Sync.
- Theo dõi trạng thái sync và health của pod/PVC.

### 8. Scale lên
- **GUI không hỗ trợ trực tiếp**: Dùng CLI:
  ```bash
  kubectl scale statefulset <statefulset-name> --replicas=<original-replicas>
  ```

### 9. Xác nhận trên GUI
- View Resource tree: Kiểm tra PVC size mới.
- View Pods: Kiểm tra logs/events.
- Nếu cần resize filesystem, vẫn cần CLI.

### Lưu ý cho GUI
- **Hạn chế**: GUI không thay thế CLI cho scale/orphan. Nếu cụm có custom action/plugin, có thể tích hợp để thực hiện qua GUI.
- **Orphaned Resources Monitoring**: Nếu bật, cấu hình `ignore` cho PVC hoặc tắt prune để tránh xóa.

---

## Lưu ý quan trọng

- **Ceph và resize**:
  - Ceph CSI driver (3.0+) hỗ trợ volume expansion tốt cho RBD và CephFS. Đảm bảo driver được cập nhật:
    ```bash
    kubectl get pods -n kube-system | grep ceph-csi
    ```
  - Với Ceph RBD, resize tự động trên volume (không cần resize filesystem). Với CephFS, filesystem (ext4/xfs) có thể cần resize thủ công.
  - Kiểm tra Ceph cluster health:
    ```bash
    ssh <ceph-admin-node> ceph -s
    ```

- **An toàn với `kubectl`**:
  - Sử dụng `kubectl` tránh nguy cơ ArgoCD xóa PVC mồ côi do prune. Sau khi resize, đồng bộ Git để tránh drift.
  - Backup dữ liệu (hoặc snapshot) là bắt buộc trước khi thực hiện.

- **ArgoCD và prune**:
  - Nếu bật Orphaned Resources Monitoring, PVC mồ côi có thể bị xóa khi sync với `prune=true`. Dùng `--prune=false` hoặc bỏ chọn "Prune Resources" trên GUI.
  - Cấu hình sync policy:
    ```yaml
    spec:
      syncPolicy:
        automated:
          prune: false  # Ngăn xóa resource mồ côi
    ```

- **Downtime**:
  - Scale về 0 gây downtime ngắn. Với high availability, dùng multiple replicas hoặc rolling update (dù khó hơn với resize PVC).

- **Test trước**:
  - Thử trên môi trường dev/staging để xác nhận không có lỗi.
  - Đảm bảo Ceph pool có đủ dung lượng và CSI driver hỗ trợ expansion.

---

## Kết luận

Để tăng kích thước PVC với Ceph trong cụm Kubernetes và ArgoCD:
1. Sử dụng `kubectl` (scale về 0, xóa với `--cascade=orphan`, apply manifest, scale lên) là cách an toàn nhất, tránh nguy cơ ArgoCD xóa PVC mồ côi.
2. Ceph CSI driver hỗ trợ resize tốt, nhưng cần kiểm tra `allowVolumeExpansion: true` và Ceph pool capacity.
3. Sau khi resize, đồng bộ Git và sync ArgoCD với `--prune=false` để tránh drift.
4. GUI ArgoCD phù hợp cho sync/monitor, nhưng cần CLI cho scale/orphan.

Nếu bạn cung cấp thêm chi tiết (e.g., manifest YAML, Ceph CSI version, Ceph RBD hay CephFS), tôi có thể tối ưu hóa hướng dẫn hơn!