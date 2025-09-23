# Cài đặt Harbor trên Kubernetes với Trivy

## 1. Yêu cầu hệ thống

- Kubernetes cluster (v1.20+)
- Helm 3.x
- Storage class có sẵn
- Ingress controller (nginx, traefik, ...)
- Certificate (có thể dùng cert-manager)

## 2. Cài đặt Harbor bằng Helm

### Bước 1: Thêm Harbor Helm repository

```bash
helm repo add harbor https://helm.goharbor.io
helm repo update
```

### Bước 2: Tạo namespace cho Harbor

```bash
kubectl create namespace harbor-system
```

### Bước 3: Tạo file values.yaml để cấu hình

```yaml
# values.yaml
expose:
  type: ingress
  tls:
    enabled: true
    certSource: secret
    secret:
      secretName: harbor-tls
  ingress:
    hosts:
      core: harbor.example.com
    className: nginx
    annotations:
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      nginx.ingress.kubernetes.io/proxy-body-size: "0"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "600"

# Cấu hình database ngoài (PostgreSQL)
database:
  type: external
  external:
    host: postgres-service
    port: "5432"
    username: "harbor"
    password: "harbor123"
    coreDatabase: "registry"

# Cấu hình Redis ngoài
redis:
  type: external
  external:
    addr: "redis-service:6379"

# Cấu hình storage
persistence:
  enabled: true
  resourcePolicy: "keep"
  persistentVolumeClaim:
    registry:
      storageClass: "fast-ssd"
      size: 50Gi
    database:
      storageClass: "fast-ssd" 
      size: 10Gi
    redis:
      storageClass: "fast-ssd"
      size: 5Gi

# Cấu hình admin
harborAdminPassword: "Harbor12345"

# Cấu hình Trivy Scanner
trivy:
  enabled: true
  image:
    repository: aquasec/trivy
    tag: 0.46.0
  resources:
    requests:
      cpu: 200m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi

# Cấu hình scanner
scanner:
  enabled: true

# Metrics và monitoring
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
```

### Bước 4: Cài đặt Harbor

```bash
helm install harbor harbor/harbor \
  --namespace harbor-system \
  --values values.yaml \
  --version 1.13.0
```

### Bước 5: Tạo TLS certificate (nếu cần)

```yaml
# harbor-tls-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: harbor-tls
  namespace: harbor-system
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTi... # base64 encoded cert
  tls.key: LS0tLS1CRUdJTi... # base64 encoded key
```

```bash
kubectl apply -f harbor-tls-secret.yaml
```

## 3. Cấu hình Trivy Scanner

### Bước 1: Kiểm tra Trivy đã được enable

```bash
kubectl get pods -n harbor-system | grep trivy
```

### Bước 2: Cấu hình Trivy trong Harbor UI

1. Đăng nhập vào Harbor UI: `https://harbor.example.com`
2. Vào **Administration** → **Interrogation Services**
3. Kiểm tra Trivy scanner đã được đăng ký
4. Nếu chưa có, thêm scanner mới:
   - Name: `Trivy`
   - Endpoint: `http://harbor-trivy:8080`
   - Authorization: `None`

### Bước 3: Cấu hình Project để auto-scan

```yaml
# project-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: harbor-project-config
  namespace: harbor-system
data:
  config.yaml: |
    projects:
      - name: "library"
        public: false
        vulnerability_scanning: true
        auto_scan: true
        severity: "High"
```

## 4. Ví dụ sử dụng Harbor trong Kubernetes

### Bước 1: Tạo Docker Registry Secret

```bash
kubectl create secret docker-registry harbor-secret \
  --docker-server=harbor.example.com \
  --docker-username=admin \
  --docker-password=Harbor12345 \
  --docker-email=admin@example.com
```

### Bước 2: Build và push image lên Harbor

```bash
# Tag image
docker tag my-app:latest harbor.example.com/library/my-app:v1.0.0

# Login vào Harbor
docker login harbor.example.com

# Push image
docker push harbor.example.com/library/my-app:v1.0.0
```

### Bước 3: Deploy application sử dụng image từ Harbor

#### Cách 1: Sử dụng imagePullSecrets (Bắt buộc nếu Harbor private)

```yaml
# deployment-with-secret.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      imagePullSecrets:
        - name: harbor-secret
      containers:
        - name: my-app
          image: harbor.example.com/library/my-app:v1.0.0
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: my-app-service
spec:
  selector:
    app: my-app
  ports:
    - port: 80
      targetPort: 8080
  type: ClusterIP
```

#### Cách 2: Gán secret vào ServiceAccount (Khuyến nghị)

```yaml
# service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: default
  labels:
    app: my-app
  annotations:
    description: "Service account for my-app with Harbor registry access"
imagePullSecrets:
  - name: harbor-secret
---
# deployment-with-sa.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      serviceAccountName: my-app-sa  # Sử dụng ServiceAccount đã cấu hình
      containers:
        - name: my-app
          image: harbor.example.com/library/my-app:v1.0.0
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          # Container có thể truy cập ServiceAccount token
          env:
            - name: SA_TOKEN_PATH
              value: /var/run/secrets/kubernetes.io/serviceaccount/token
          volumeMounts:
            - name: sa-token
              mountPath: /var/run/secrets/kubernetes.io/serviceaccount
              readOnly: true
      volumes:
        - name: sa-token
          projected:
            sources:
            - serviceAccountToken:
                path: token
                expirationSeconds: 3600
```

#### Cách 3: Nếu Harbor project là public (không cần secret)

```yaml
# deployment-public.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      # Không cần imagePullSecrets nếu project là public
      containers:
        - name: my-app
          image: harbor.example.com/library/my-app:v1.0.0
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
```

```bash
kubectl apply -f deployment-with-secret.yaml
# hoặc
kubectl apply -f service-account.yaml
kubectl apply -f deployment-with-sa.yaml
```

## 7. Monitoring và Security

### Tạo secret trên namespace khác

```bash
# Tạo secret trên namespace production
kubectl create secret docker-registry harbor-secret \
  --docker-server=harbor.example.com \
  --docker-username=admin \
  --docker-password=Harbor12345 \
  --docker-email=admin@example.com \
  --namespace=production

# Hoặc copy secret từ namespace khác
kubectl get secret harbor-secret --namespace=default -o yaml | \
  sed 's/namespace: default/namespace: production/' | \
  kubectl apply -f -
```

### Tự động tạo secret cho tất cả namespace

```yaml
# harbor-secret-template.yaml
apiVersion: v1
kind: Secret
metadata:
  name: harbor-secret
  namespace: default
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: eyJhdXRocyI6eyJoYXJib3IuZXhhbXBsZS5jb20iOnsidXNlcm5hbWUiOiJhZG1pbiIsInBhc3N3b3JkIjoiSGFyYm9yMTIzNDUiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwiYXV0aCI6IllXUnRhVzQ2U0dGeVltOXlNVEl6TkRVPSJ9fX0=
```

```bash
# Script tạo secret cho tất cả namespace
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  kubectl apply -f harbor-secret-template.yaml -n $ns
done
```

### Cấu hình scan policy

```yaml
# scan-policy.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: harbor-scan-policy
data:
  policy.yaml: |
    rules:
      - name: "block-critical"
        disabled: false
        priority: 1
        action: "deny"
        template: "vulnerability"
        parameters:
          severity: "Critical"
      - name: "block-high"
        disabled: false
        priority: 2
        action: "deny" 
        template: "vulnerability"
        parameters:
          severity: "High"
      - name: "warn-medium"
        disabled: false
        priority: 3
        action: "warn"
        template: "vulnerability"  
        parameters:
          severity: "Medium"
```

### Prometheus monitoring

```yaml
# servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: harbor-metrics
  namespace: harbor-system
spec:
  selector:
    matchLabels:
      app: harbor
      component: core
  endpoints:
    - port: http-metrics
      path: /metrics
      interval: 30s
```

## 7. Backup và Restore

### Backup script

```bash
#!/bin/bash
# backup-harbor.sh

NAMESPACE="harbor-system"
BACKUP_DIR="/backup/harbor-$(date +%Y%m%d-%H%M%S)"

mkdir -p $BACKUP_DIR

# Backup PVCs
kubectl get pvc -n $NAMESPACE -o yaml > $BACKUP_DIR/pvcs.yaml

# Backup secrets
kubectl get secrets -n $NAMESPACE -o yaml > $BACKUP_DIR/secrets.yaml

# Backup configmaps  
kubectl get configmaps -n $NAMESPACE -o yaml > $BACKUP_DIR/configmaps.yaml

# Database backup (if using internal postgres)
kubectl exec -n $NAMESPACE harbor-database-0 -- pg_dumpall -U postgres > $BACKUP_DIR/database.sql

echo "Backup completed: $BACKUP_DIR"
```

## 8. Troubleshooting

### Kiểm tra status các pods

```bash
kubectl get pods -n harbor-system
kubectl describe pod harbor-core-xxx -n harbor-system
kubectl logs harbor-trivy-xxx -n harbor-system
```

### Kiểm tra Trivy scanner

```bash
# Test trivy endpoint
kubectl port-forward -n harbor-system svc/harbor-trivy 8080:8080

# Test scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"registry":{"url":"harbor.example.com","username":"admin","password":"Harbor12345"},"artifact":{"repository":"library/my-app","tag":"v1.0.0"}}'
```

### Debug connectivity

```bash
# Test database connection
kubectl run -it --rm debug --image=postgres:13 --restart=Never -- psql -h postgres-service -U harbor -d registry

# Test Redis connection  
kubectl run -it --rm debug --image=redis:6 --restart=Never -- redis-cli -h redis-service ping
```

## Kết luận

Harbor với Trivy scanner cung cấp giải pháp registry hoàn chỉnh với khả năng quét bảo mật image. Việc tích hợp với Kubernetes giúp tự động hóa quy trình CI/CD và đảm bảo security compliance cho container images.