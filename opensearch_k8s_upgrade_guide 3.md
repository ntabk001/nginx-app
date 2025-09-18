# Hướng dẫn Upgrade OpenSearch và OpenSearch Dashboard trên Kubernetes

## Mục lục
1. [Chuẩn bị trước khi upgrade](#chuẩn-bị-trước-khi-upgrade)
2. [Backup dữ liệu](#backup-dữ-liệu)
3. [Upgrade OpenSearch](#upgrade-opensearch)
4. [Upgrade OpenSearch Dashboard](#upgrade-opensearch-dashboard)
5. [Kiểm tra sau upgrade](#kiểm-tra-sau-upgrade)
6. [Troubleshooting](#troubleshooting)

---

## Chuẩn bị trước khi upgrade

### 1. Kiểm tra phiên bản hiện tại
```bash
# Kiểm tra phiên bản OpenSearch
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/nodes?v&h=name,version"

# Kiểm tra phiên bản OpenSearch Dashboard
kubectl get pods -n opensearch -o jsonpath='{.items[?(@.metadata.labels.app=="opensearch-dashboards")].spec.containers[0].image}'
```

### 2. Kiểm tra trạng thái cluster
```bash
# Kiểm tra health cluster
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cluster/health?pretty"

# Kiểm tra nodes
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/nodes?v"

# Kiểm tra indices
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/indices?v"
```

### 3. Review upgrade compatibility
- Kiểm tra [compatibility matrix](https://opensearch.org/docs/latest/upgrade-to/index/) giữa các phiên bản
- Đọc release notes của phiên bản đích
- Kiểm tra breaking changes

### 4. Chuẩn bị môi trường
```bash
# Tạo namespace riêng cho backup nếu cần
kubectl create namespace opensearch-backup

# Kiểm tra storage class
kubectl get storageclass

# Kiểm tra resources hiện tại
kubectl top pods -n opensearch
```

---

## Backup dữ liệu

### 1. Backup toàn bộ cluster (Snapshot)
```bash
# Tạo repository backup
kubectl exec -n opensearch opensearch-master-0 -- curl -X PUT "localhost:9200/_snapshot/backup_repo" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/opensearch/backup"
  }
}'

# Tạo snapshot
kubectl exec -n opensearch opensearch-master-0 -- curl -X PUT "localhost:9200/_snapshot/backup_repo/pre_upgrade_$(date +%Y%m%d_%H%M%S)" -H 'Content-Type: application/json' -d'
{
  "indices": "*",
  "ignore_unavailable": true,
  "include_global_state": true,
  "metadata": {
    "taken_by": "k8s_upgrade_script",
    "taken_because": "Pre-upgrade backup"
  }
}'
```

### 2. Backup configurations
```bash
# Backup Helm values
helm get values opensearch -n opensearch > opensearch-values-backup.yaml
helm get values opensearch-dashboards -n opensearch > dashboards-values-backup.yaml

# Backup Kubernetes resources
kubectl get all -n opensearch -o yaml > opensearch-k8s-resources-backup.yaml
```

### 3. Backup persistent volumes
```bash
# Lấy danh sách PVCs
kubectl get pvc -n opensearch

# Tạo snapshot PVC (nếu storage class hỗ trợ)
kubectl patch pvc opensearch-master-opensearch-master-0 -n opensearch -p '{"metadata":{"annotations":{"snapshot.alpha.kubernetes.io/snapshot":"pre-upgrade-snapshot"}}}'
```

---

## Upgrade OpenSearch với ArgoCD

### Phương pháp 1: GitOps Workflow (Khuyến nghị)

#### 1. Chuẩn bị Git Repository
```bash
# Cấu trúc thư mục GitOps
opensearch-gitops/
├── environments/
│   ├── staging/
│   │   ├── opensearch/
│   │   │   ├── values.yaml
│   │   │   └── kustomization.yaml
│   │   └── opensearch-dashboards/
│   └── production/
│       ├── opensearch/
│       │   ├── values.yaml
│       │   └── kustomization.yaml
│       └── opensearch-dashboards/
├── base/
│   ├── opensearch/
│   │   ├── Chart.yaml
│   │   └── values.yaml
│   └── opensearch-dashboards/
└── scripts/
    └── pre-upgrade-checks.sh
```

#### 2. Disable ArgoCD Auto-Sync (Quan trọng)
```bash
# Tạm dừng auto-sync để kiểm soát upgrade process
argocd app patch opensearch --patch '{"spec": {"syncPolicy": {"automated": null}}}' --type merge

# Hoặc qua UI: ArgoCD → App → Settings → Sync Policy → Disable Auto-Sync
```

#### 3. Pre-upgrade cluster settings
```bash
# Disable shard allocation trước khi upgrade
kubectl exec -n opensearch opensearch-master-0 -- curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": "primaries"
  }
}'

# Perform synced flush
kubectl exec -n opensearch opensearch-master-0 -- curl -X POST "localhost:9200/_flush/synced"
```

#### 4. Update Git Repository
```yaml
# environments/production/opensearch/values.yaml
image:
  repository: opensearchproject/opensearch
  tag: "2.11.0" # Update version
  pullPolicy: IfNotPresent

# Thêm upgrade strategy
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1

# Thêm health check configurations
readinessProbe:
  initialDelaySeconds: 60
  periodSeconds: 30
  timeoutSeconds: 10

livenessProbe:
  initialDelaySeconds: 90
  periodSeconds: 30
  timeoutSeconds: 10
```

#### 5. Staged Upgrade qua ArgoCD
```bash
# Commit changes to git
git add environments/production/opensearch/values.yaml
git commit -m "upgrade: opensearch to version 2.11.0"
git push origin main

# Sync từng component một cách thủ công
# Sync master nodes trước
argocd app sync opensearch --resource apps:StatefulSet:opensearch-master

# Đợi master nodes healthy
kubectl wait --for=condition=ready pod -l component=opensearch-master -n opensearch --timeout=600s

# Kiểm tra cluster health
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cluster/health"

# Sync data nodes
argocd app sync opensearch --resource apps:StatefulSet:opensearch-data

# Đợi data nodes healthy
kubectl wait --for=condition=ready pod -l component=opensearch-data -n opensearch --timeout=600s
```

#### 6. Post-upgrade cluster settings
```bash
# Re-enable shard allocation
kubectl exec -n opensearch opensearch-master-0 -- curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": null
  }
}'
```

### Phương pháp 2: Blue-Green Deployment với ArgoCD

#### 1. Tạo Green Environment
```yaml
# environments/production/opensearch-green/values.yaml
nameOverride: opensearch-green
fullnameOverride: opensearch-green

image:
  tag: "2.11.0"

service:
  name: opensearch-green
  
# Sử dụng cùng PVCs (quan trọng)
persistence:
  enabled: true
  existingClaim: opensearch-master-opensearch-master # Reuse existing PVCs
```

#### 2. Deploy Green Environment
```bash
# Tạo ArgoCD Application cho green environment
argocd app create opensearch-green \
  --repo https://github.com/your-org/opensearch-gitops \
  --path environments/production/opensearch-green \
  --dest-server https://kubernetes.default.svc \
  --dest-namespace opensearch-green

# Sync green environment
argocd app sync opensearch-green
```

#### 3. Data Migration (nếu cần)
```bash
# Restore snapshot to green environment
kubectl exec -n opensearch-green opensearch-green-master-0 -- curl -X POST "localhost:9200/_snapshot/backup_repo/pre_upgrade_snapshot/_restore"
```

#### 4. Switch Traffic
```bash
# Update ingress hoặc service selector
kubectl patch ingress opensearch-ingress -n opensearch --type='merge' -p='{"spec":{"rules":[{"host":"opensearch.example.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"opensearch-green","port":{"number":9200}}}}]}}]}}'
```

### Phương pháp 3: Upgrade qua ArgoCD UI (Step-by-step)

#### Bước 1: Chuẩn bị trước upgrade trên UI
1. **Truy cập ArgoCD UI** → Applications → Chọn `opensearch`
2. **Disable Auto-Sync**:
   - Click **App Details** tab
   - Tìm **Sync Policy** section
   - Click **Disable Auto-Sync**
   - Confirm action

3. **Kiểm tra Application Health**:
   - Đảm bảo status là **Healthy** và **Synced**
   - Check tất cả resources đều green

#### Bước 2: Update Git Repository (Prerequisite)
```bash
# Update values.yaml trong git repo
# environments/production/opensearch/values.yaml
image:
  tag: "2.11.0"  # Thay đổi version

# Commit và push
git add .
git commit -m "upgrade: opensearch to v2.11.0"
git push origin main
```

#### Bước 3: Pre-upgrade Tasks qua UI
1. **Mở Terminal/Exec** từ ArgoCD UI:
   - Click vào **opensearch-master-0** pod
   - Click **Terminal** tab
   - Execute commands:

```bash
# Disable shard allocation
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": "primaries"
  }
}'

# Perform synced flush
curl -X POST "localhost:9200/_flush/synced"
```

#### Bước 4: Selective Resource Sync (Master Nodes)
1. **Refresh Repository**:
   - Click **Refresh** button (icon reload)
   - Chọn **Hard Refresh** nếu cần

2. **Sync Master StatefulSet**:
   - Tìm **StatefulSet/opensearch-master** trong resource tree
   - Click vào resource
   - Click **Sync** button
   - Trong Sync dialog:
     - Check **Replace** option
     - Check **Force** nếu cần
     - Click **Synchronize**

3. **Monitor Master Upgrade**:
   - Watch **Pod Status** thay đổi
   - Pods sẽ restart từng cái một
   - Đợi tất cả master pods **Running** và **Ready**

#### Bước 5: Health Check Master Nodes qua UI
1. **Check Pod Logs**:
   - Click vào **opensearch-master-0** pod
   - Click **Logs** tab
   - Verify no errors during startup

2. **Cluster Health Check**:
   - Vào **Terminal** tab của master pod
   - Execute:
```bash
curl -X GET "localhost:9200/_cluster/health?pretty"
curl -X GET "localhost:9200/_cat/nodes?v"
```

#### Bước 6: Sync Data Nodes
1. **Sync Data StatefulSet**:
   - Tìm **StatefulSet/opensearch-data** 
   - Repeat sync process như master nodes
   - Monitor pod restart process

2. **Wait for Cluster Stability**:
   - All pods **Running**
   - Cluster health **Green** hoặc **Yellow**

#### Bước 7: Post-upgrade Tasks
1. **Re-enable Shard Allocation**:
   - Vào terminal của master pod
   - Execute:
```bash
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": null
  }
}'
```

2. **Final Health Check**:
```bash
curl -X GET "localhost:9200/_cluster/health?pretty"
curl -X GET "localhost:9200/_cat/indices?v"
```

#### Bước 8: Upgrade Dashboard qua UI
1. **Update Dashboard Git Config** (nếu cần)
2. **Sync opensearch-dashboards** Application:
   - Navigate to **opensearch-dashboards** app
   - Click **Sync**
   - Monitor deployment restart

#### Bước 9: Final Verification
1. **Application Overview**:
   - Both applications status **Healthy** ✓
   - All resources **Synced** ✓

2. **Test Functionality**:
   - Access Dashboard UI
   - Test search queries
   - Verify indices

#### Bước 10: Re-enable Auto-Sync (Optional)
1. **App Details** → **Sync Policy**
2. **Enable Auto-Sync** nếu muốn
3. Set sync options như:
   - **Prune**: true
   - **Self Heal**: true

### UI-based Troubleshooting

#### 1. Sync Failures
**Từ ArgoCD UI:**
- Click **Sync Status** để xem lỗi
- **Events** tab showing error details
- **Diff** tab để compare desired vs actual state

**Common Actions:**
- **Retry Sync** with different options
- **Force Replace** nếu có conflicts
- **Manual Resource Deletion** rồi sync lại

#### 2. Resource Stuck Issues
1. **Resource Details**:
   - Click vào stuck resource
   - Check **Events** và **YAML**
   - Look for error messages

2. **Manual Intervention**:
   - **Delete** resource từ UI
   - **Sync** lại để recreate

#### 3. Health Check Failures
1. **Application Health**:
   - Red status → Check individual resources
   - **Logs** tab của failing pods
   - **Events** tab cho system events

2. **Custom Health Checks**:
   - Review **Resource Health** details
   - Override health check nếu cần

### UI Monitoring During Upgrade

#### Real-time Monitoring
1. **Resource Tree View**:
   - Color-coded status của tất cả resources
   - Real-time updates khi pods restart

2. **Timeline View**:
   - Sync history
   - Operation details và timing

3. **Live Logs**:
   - Multiple pod logs simultaneously
   - Filter by container/pod name

#### Progress Tracking
- **Sync Progress Bar** during operations
- **Resource Status Icons** (green/yellow/red)
- **Pod Readiness Indicators**
- **Events Stream** real-time

### ArgoCD UI Tips & Tricks

#### Efficient Navigation
- **Bookmark Applications** để quick access
- **Use Search/Filter** trong resource tree
- **Keyboard shortcuts** (k for help)

#### Batch Operations
- **Select multiple resources** for bulk sync
- **Application Sets** để manage multiple environments

#### Custom Views
- **Compact Tree View** để see more resources
- **Network View** để understand dependencies
- **Pod View** để focus on workloads

#### Emergency Actions
- **Quick Rollback**: Previous sync revision
- **Emergency Sync**: Force immediate sync
- **Resource Override**: Manual YAML editing

### Best Practices với UI

1. **Always check Diff** before sync
2. **Monitor Events tab** during operations  
3. **Use terminal access** for health checks
4. **Keep git history clean** cho easy rollbacks
5. **Test UI flows** trên staging environment

### Upgrade OpenSearch Dashboard với ArgoCD

#### 1. Update Dashboard values
```yaml
# environments/production/opensearch-dashboards/values.yaml
image:
  repository: opensearchproject/opensearch-dashboards
  tag: "2.11.0"

# Update OpenSearch connection nếu cần
opensearchHosts: "https://opensearch-master:9200"

# Health checks
readinessProbe:
  httpGet:
    path: /api/status
    port: 5601
  initialDelaySeconds: 30
  timeoutSeconds: 10

livenessProbe:
  httpGet:
    path: /api/status
    port: 5601
  initialDelaySeconds: 60
  timeoutSeconds: 10
```

#### 2. Sync Dashboard
```bash
# Commit changes
git add environments/production/opensearch-dashboards/values.yaml
git commit -m "upgrade: opensearch-dashboards to 2.11.0"
git push origin main

# Sync dashboard
argocd app sync opensearch-dashboards
```

### ArgoCD-specific Troubleshooting

#### 1. Sync Issues
```bash
# Force sync nếu có conflicts
argocd app sync opensearch --force

# Hard refresh nếu cần
argocd app diff opensearch --hard-refresh

# Xem sync status
argocd app get opensearch
```

#### 2. Rollback với ArgoCD
```bash
# Rollback về commit trước
git revert HEAD
git push origin main

# Sync rollback
argocd app sync opensearch

# Hoặc rollback về revision cụ thể
argocd app rollback opensearch --revision=<previous-revision>
```

#### 3. Monitor Upgrade Progress
```bash
# Xem real-time status
argocd app get opensearch --refresh

# Xem logs
argocd app logs opensearch --follow

# Xem events
kubectl get events -n opensearch --sort-by='.lastTimestamp'
```

### Best Practices với ArgoCD

#### 1. GitOps Workflow
```bash
# Luôn test trên staging trước
argocd app sync opensearch-staging
# Verify health
# Promote to production

# Sử dụng branch strategy
git checkout -b upgrade/opensearch-2.11.0
# Make changes
# Create PR
# Review và merge
```

#### 2. Application Health Checks
```yaml
# Trong ArgoCD Application manifest
spec:
  syncPolicy:
    syncOptions:
    - CreateNamespace=true
    - PruneLast=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
  
  # Custom health check
  health:
    - group: apps
      kind: StatefulSet
      check: |
        health_status = {}
        if obj.status ~= nil then
          if obj.status.readyReplicas ~= nil and obj.status.replicas ~= nil then
            if obj.status.readyReplicas == obj.status.replicas then
              health_status.status = "Healthy"
              health_status.message = "All replicas are ready"
            else
              health_status.status = "Progressing"
              health_status.message = "Waiting for replicas to be ready"
            end
          end
        end
        return health_status
```

#### 3. Pre/Post Upgrade Hooks
```yaml
# Pre-upgrade hook
apiVersion: batch/v1
kind: Job
metadata:
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  template:
    spec:
      containers:
      - name: pre-upgrade-check
        image: curlimages/curl
        command: ["/bin/sh"]
        args:
        - -c
        - |
          # Health check script
          ./scripts/pre-upgrade-checks.sh
```

---

## Upgrade OpenSearch Dashboard

### 1. Kiểm tra compatibility
```bash
# Đảm bảo Dashboard version tương thích với OpenSearch version
```

### 2. Upgrade Dashboard
```bash
# Sử dụng Helm
helm upgrade opensearch-dashboards opensearch/opensearch-dashboards \
  --namespace opensearch \
  --version 2.11.0 \
  --values dashboards-values-backup.yaml \
  --set image.tag=2.11.0

# Hoặc update deployment trực tiếp
kubectl set image deployment/opensearch-dashboards opensearch-dashboards=opensearchproject/opensearch-dashboards:2.11.0 -n opensearch
```

### 3. Restart Dashboard pods
```bash
kubectl rollout restart deployment/opensearch-dashboards -n opensearch
kubectl rollout status deployment/opensearch-dashboards -n opensearch
```

---

## Kiểm tra sau upgrade

### 1. Kiểm tra version
```bash
# Kiểm tra OpenSearch version
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200" | jq '.version'

# Kiểm tra tất cả nodes
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/nodes?v&h=name,version"
```

### 2. Kiểm tra cluster health
```bash
# Health overview
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cluster/health?pretty"

# Chi tiết về cluster
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cluster/stats?pretty"

# Kiểm tra pending tasks
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cluster/pending_tasks?pretty"
```

### 3. Kiểm tra nodes
```bash
# Danh sách nodes
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/nodes?v"

# Chi tiết từng node
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_nodes/stats?pretty"

# Kiểm tra disk usage
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/allocation?v"
```

### 4. Kiểm tra indices và data
```bash
# Danh sách indices
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/indices?v"

# Kiểm tra shard status
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/shards?v"

# Kiểm tra recovery process
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/recovery?v&active_only=true"

# Test search functionality
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match_all": {}
  },
  "size": 1
}'
```

### 5. Kiểm tra OpenSearch Dashboard
```bash
# Kiểm tra pods
kubectl get pods -n opensearch -l app=opensearch-dashboards

# Kiểm tra logs
kubectl logs -n opensearch deployment/opensearch-dashboards

# Test connectivity
kubectl port-forward -n opensearch svc/opensearch-dashboards 5601:5601 &
curl -I http://localhost:5601
```

### 6. Kiểm tra plugins
```bash
# Liệt kê plugins đã cài
kubectl exec -n opensearch opensearch-master-0 -- /usr/share/opensearch/bin/opensearch-plugin list

# Kiểm tra plugin settings
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_nodes/plugins?pretty"
```

### 7. Performance tests
```bash
# Index test document
kubectl exec -n opensearch opensearch-master-0 -- curl -X POST "localhost:9200/test-index/_doc" -H 'Content-Type: application/json' -d'
{
  "timestamp": "'$(date -Iseconds)'",
  "message": "Test document after upgrade",
  "test": true
}'

# Search test
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/test-index/_search?pretty"

# Bulk indexing test
kubectl exec -n opensearch opensearch-master-0 -- curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/json' --data-binary "@test-bulk-data.json"
```

### 8. Monitoring checks
```bash
# Kiểm tra metrics endpoint
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_prometheus/metrics"

# Kiểm tra thread pools
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/thread_pool?v"

# Memory usage
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_nodes/stats/jvm?pretty"
```

---

## Troubleshooting

### Common Issues

#### 1. Cluster Red Status
```bash
# Kiểm tra unassigned shards
kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason"

# Force allocate shard
kubectl exec -n opensearch opensearch-master-0 -- curl -X POST "localhost:9200/_cluster/reroute" -H 'Content-Type: application/json' -d'
{
  "commands": [
    {
      "allocate_empty_primary": {
        "index": "INDEX_NAME",
        "shard": 0,
        "node": "NODE_NAME",
        "accept_data_loss": true
      }
    }
  ]
}'
```

#### 2. Memory Issues
```bash
# Tăng heap size
kubectl patch statefulset opensearch-master -n opensearch --type='merge' -p='{"spec":{"template":{"spec":{"containers":[{"name":"opensearch","env":[{"name":"OPENSEARCH_JAVA_OPTS","value":"-Xms2g -Xmx2g"}]}]}}}}'
```

#### 3. Dashboard Connection Issues
```bash
# Kiểm tra opensearch_dashboards.yml config
kubectl exec -n opensearch opensearch-dashboards-xxx -- cat /usr/share/opensearch-dashboards/config/opensearch_dashboards.yml

# Update config nếu cần
kubectl create configmap dashboards-config --from-file=opensearch_dashboards.yml -n opensearch
```

#### 4. Rollback procedures
```bash
# Rollback Helm deployment
helm rollback opensearch -n opensearch
helm rollback opensearch-dashboards -n opensearch

# Restore from snapshot
kubectl exec -n opensearch opensearch-master-0 -- curl -X POST "localhost:9200/_snapshot/backup_repo/SNAPSHOT_NAME/_restore"
```

### Health Check Script
```bash
#!/bin/bash

echo "=== OpenSearch Cluster Health Check ==="
kubectl exec -n opensearch opensearch-master-0 -- curl -s localhost:9200/_cluster/health | jq '.'

echo -e "\n=== Node Status ==="
kubectl exec -n opensearch opensearch-master-0 -- curl -s localhost:9200/_cat/nodes?v

echo -e "\n=== Index Status ==="
kubectl exec -n opensearch opensearch-master-0 -- curl -s localhost:9200/_cat/indices?v

echo -e "\n=== Shard Status ==="
kubectl exec -n opensearch opensearch-master-0 -- curl -s localhost:9200/_cat/shards?v | grep -E "(UNASSIGNED|INITIALIZING)"

echo -e "\n=== Pod Status ==="
kubectl get pods -n opensearch

echo -e "\n=== Dashboard Status ==="
kubectl get svc -n opensearch opensearch-dashboards
```

---

## Best Practices

1. **Luôn backup trước khi upgrade**
2. **Test upgrade trên staging environment trước**
3. **Upgrade từng node một (rolling upgrade)**
4. **Monitor cluster health trong quá trình upgrade**
5. **Chuẩn bị rollback plan**
6. **Đọc kỹ release notes và breaking changes**
7. **Update monitoring và alerting rules sau upgrade**

---

## Tài liệu tham khảo

- [OpenSearch Upgrade Guide](https://opensearch.org/docs/latest/upgrade-to/)
- [Kubernetes StatefulSet Updates](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#update-strategies)
- [Helm Upgrade Guide](https://helm.sh/docs/helm/helm_upgrade/)
- [OpenSearch Snapshots API](https://opensearch.org/docs/latest/api-reference/snapshots/)