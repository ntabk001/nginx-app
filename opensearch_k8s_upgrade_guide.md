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

## Upgrade OpenSearch

### 1. Disable shard allocation (Rolling upgrade)
```bash
kubectl exec -n opensearch opensearch-master-0 -- curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": "primaries"
  }
}'
```

### 2. Perform synced flush
```bash
kubectl exec -n opensearch opensearch-master-0 -- curl -X POST "localhost:9200/_flush/synced"
```

### 3. Upgrade từng node (Rolling upgrade)
```bash
# Upgrade master nodes trước
for i in {0..2}; do
  echo "Upgrading opensearch-master-$i"
  
  # Scale down node
  kubectl patch statefulset opensearch-master -n opensearch --type='merge' -p='{"spec":{"replicas":'$((3-i-1))'}}'
  
  # Đợi pod terminate
  kubectl wait --for=delete pod/opensearch-master-$i -n opensearch --timeout=300s
  
  # Update image version trong StatefulSet
  kubectl patch statefulset opensearch-master -n opensearch --type='merge' -p='{"spec":{"template":{"spec":{"containers":[{"name":"opensearch","image":"opensearchproject/opensearch:2.11.0"}]}}}}'
  
  # Scale up
  kubectl patch statefulset opensearch-master -n opensearch --type='merge' -p='{"spec":{"replicas":'$((3-i))'}}'
  
  # Đợi pod ready
  kubectl wait --for=condition=ready pod/opensearch-master-$i -n opensearch --timeout=600s
  
  # Kiểm tra node join cluster
  kubectl exec -n opensearch opensearch-master-0 -- curl -X GET "localhost:9200/_cat/nodes?v"
  
  sleep 30
done
```

### 4. Upgrade data nodes
```bash
# Tương tự cho data nodes
for i in {0..2}; do
  echo "Upgrading opensearch-data-$i"
  
  kubectl patch statefulset opensearch-data -n opensearch --type='merge' -p='{"spec":{"replicas":'$((3-i-1))'}}'
  kubectl wait --for=delete pod/opensearch-data-$i -n opensearch --timeout=300s
  kubectl patch statefulset opensearch-data -n opensearch --type='merge' -p='{"spec":{"template":{"spec":{"containers":[{"name":"opensearch","image":"opensearchproject/opensearch:2.11.0"}]}}}}'
  kubectl patch statefulset opensearch-data -n opensearch --type='merge' -p='{"spec":{"replicas":'$((3-i))'}}'
  kubectl wait --for=condition=ready pod/opensearch-data-$i -n opensearch --timeout=600s
  
  sleep 30
done
```

### 5. Re-enable shard allocation
```bash
kubectl exec -n opensearch opensearch-master-0 -- curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": null
  }
}'
```

### 6. Upgrade sử dụng Helm (Alternative approach)
```bash
# Update Helm repo
helm repo update

# Upgrade với Helm
helm upgrade opensearch opensearch/opensearch \
  --namespace opensearch \
  --version 2.11.0 \
  --values opensearch-values-backup.yaml \
  --set image.tag=2.11.0
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