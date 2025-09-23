# Elasticsearch - Tổng Quan Lý Thuyết

## 1. Giới Thiệu Elasticsearch

### Elasticsearch là gì?
Elasticsearch là một search engine và analytics engine phân tán, mã nguồn mở, được xây dựng trên Apache Lucene. Nó cho phép tìm kiếm, phân tích và lưu trữ dữ liệu theo thời gian thực với khả năng mở rộng cao.

### Đặc điểm chính:
- **Phân tán (Distributed)**: Có thể chạy trên nhiều node
- **Real-time**: Tìm kiếm và phân tích dữ liệu gần như thời gian thực
- **RESTful API**: Giao tiếp qua HTTP REST API
- **Schema-free**: Linh hoạt trong cấu trúc dữ liệu
- **Multi-tenancy**: Hỗ trợ nhiều index trong cùng một cluster

## 2. Các Khái Niệm Cơ Bản

### 2.1 Cluster (Cụm)
- Tập hợp của một hoặc nhiều node
- Được xác định bởi tên duy nhất (mặc định: "elasticsearch")
- Chứa tất cả dữ liệu và cung cấp khả năng indexing và search

### 2.2 Node (Nút)
- Một server đơn lẻ trong cluster
- Lưu trữ dữ liệu và tham gia vào việc indexing và search
- Được xác định bởi tên và UUID duy nhất

#### Các loại Node:
- **Master Node**: Quản lý cluster metadata
- **Data Node**: Lưu trữ dữ liệu và thực hiện CRUD operations
- **Ingest Node**: Tiền xử lý documents trước khi indexing
- **Coordinating Node**: Route requests và merge results

### 2.3 Index
- Tương đương với "database" trong RDBMS
- Tập hợp các documents có đặc điểm tương tự
- Tên index phải viết thường

### 2.4 Type (Đã deprecated từ 7.0)
- Tương đương với "table" trong RDBMS
- Elasticsearch 7.x+ chỉ hỗ trợ một type per index

### 2.5 Document
- Đơn vị cơ bản của thông tin
- Được biểu diễn dưới dạng JSON
- Có một ID duy nhất trong index

### 2.6 Field
- Cặp key-value trong document
- Tương đương với "column" trong RDBMS

### 2.7 Shard
- Subdivision của index
- Cho phép phân tán dữ liệu trên nhiều node
- Có hai loại: Primary shard và Replica shard

### 2.8 Replica
- Bản sao của shard
- Cung cấp high availability và tăng throughput cho read operations

## 3. Cấu Trúc Dữ Liệu và Mapping

### 3.1 Mapping
Mapping định nghĩa cách documents và fields được stored và indexed.

```json
{
  "mappings": {
    "properties": {
      "title": {
        "type": "text",
        "analyzer": "standard"
      },
      "date": {
        "type": "date",
        "format": "yyyy-MM-dd"
      },
      "price": {
        "type": "float"
      },
      "tags": {
        "type": "keyword"
      }
    }
  }
}
```

### 3.2 Các Data Types Chính

#### Text Types:
- **text**: Full-text search
- **keyword**: Exact matching, aggregations

#### Numeric Types:
- **long, integer, short, byte**
- **double, float, half_float**

#### Date Type:
- **date**: Ngày tháng với format tùy chỉnh

#### Boolean Type:
- **boolean**: true/false

#### Object Types:
- **object**: JSON object
- **nested**: Array of objects

#### Specialized Types:
- **geo_point**: Tọa độ địa lý
- **ip**: IP address
- **binary**: Base64 encoded binary data

### 3.3 Dynamic Mapping
Elasticsearch tự động detect data types khi indexing documents mới:

```json
{
  "mappings": {
    "dynamic": "true",
    "dynamic_templates": [
      {
        "strings": {
          "match_mapping_type": "string",
          "mapping": {
            "type": "text",
            "fields": {
              "raw": {
                "type": "keyword"
              }
            }
          }
        }
      }
    ]
  }
}
```

## 4. Indexing và Search

### 4.1 Indexing Process
1. Document được gửi đến coordinating node
2. Node xác định shard đích dựa trên document ID
3. Document được index vào primary shard
4. Replica shards được update

### 4.2 Search Process
1. Query được gửi đến coordinating node
2. Node broadcast query đến tất cả relevant shards
3. Mỗi shard thực hiện search và trả về results
4. Coordinating node merge và sort results

### 4.3 Query Types

#### Full-text Queries:
```json
{
  "query": {
    "match": {
      "title": "elasticsearch tutorial"
    }
  }
}
```

#### Term-level Queries:
```json
{
  "query": {
    "term": {
      "status": "published"
    }
  }
}
```

#### Compound Queries:
```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "title": "elasticsearch" } }
      ],
      "filter": [
        { "range": { "date": { "gte": "2023-01-01" } } }
      ],
      "must_not": [
        { "term": { "status": "draft" } }
      ]
    }
  }
}
```

## 5. Cấu Hình Tối Ưu

### 5.1 Cluster Settings

#### elasticsearch.yml:
```yaml
# Cluster name
cluster.name: production-cluster

# Node configuration
node.name: node-1
node.roles: [ master, data, ingest ]

# Network settings
network.host: 0.0.0.0
http.port: 9200
transport.port: 9300

# Discovery settings
discovery.seed_hosts: ["host1", "host2", "host3"]
cluster.initial_master_nodes: ["node-1", "node-2", "node-3"]

# Memory settings
bootstrap.memory_lock: true

# Path settings
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
```

### 5.2 Memory Configuration

#### JVM Heap Size:
```bash
# jvm.options
-Xms4g
-Xmx4g
```

**Quy tắc quan trọng:**
- Heap size không vượt quá 50% RAM
- Không vượt quá 32GB (compressed OOPs)
- Xms = Xmx để tránh heap resize

### 5.3 Index Settings

#### Index Template:
```json
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "refresh_interval": "30s",
      "max_result_window": 10000
    },
    "mappings": {
      "properties": {
        "timestamp": {
          "type": "date"
        },
        "message": {
          "type": "text"
        }
      }
    }
  }
}
```

### 5.4 Performance Tuning

#### Indexing Performance:
```json
{
  "settings": {
    "refresh_interval": -1,
    "number_of_replicas": 0,
    "index.translog.durability": "async",
    "index.translog.sync_interval": "30s"
  }
}
```

#### Search Performance:
```json
{
  "settings": {
    "index.requests.cache.enable": true,
    "index.queries.cache.enabled": true,
    "index.warmer.enabled": true
  }
}
```

### 5.5 Hardware Recommendations

#### RAM:
- Minimum: 8GB
- Recommended: 64GB+
- 50% cho Elasticsearch heap, 50% cho OS cache

#### CPU:
- Minimum: 4 cores
- Recommended: 16+ cores
- CPU-bound cho indexing, I/O-bound cho search

#### Storage:
- SSD strongly recommended
- RAID 0 cho performance
- Separate disks cho data và logs

#### Network:
- Minimum: 1Gbps
- Recommended: 10Gbps+ cho large clusters

## 6. Monitoring và Maintenance

### 6.1 Cluster Health
```bash
GET /_cluster/health
GET /_cluster/stats
GET /_nodes/stats
```

### 6.2 Index Management

#### Index Lifecycle Management (ILM):
```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "30d"
          }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "delete": {
        "min_age": "90d"
      }
    }
  }
}
```

### 6.3 Backup và Recovery
```bash
# Snapshot repository
PUT /_snapshot/my_repository
{
  "type": "fs",
  "settings": {
    "location": "/mount/backups/my_repository"
  }
}

# Create snapshot
PUT /_snapshot/my_repository/snapshot_1
{
  "indices": "index_1,index_2",
  "ignore_unavailable": true,
  "include_global_state": false
}
```

## 7. Security Best Practices

### 7.1 X-Pack Security
```yaml
# elasticsearch.yml
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true
```

### 7.2 User Management
```bash
# Create user
POST /_security/user/john
{
  "password": "password",
  "roles": ["kibana_user", "monitoring_user"],
  "full_name": "John Doe"
}
```

### 7.3 Index-level Security
```json
{
  "role_name": "logs_reader",
  "indices": [
    {
      "names": ["logs-*"],
      "privileges": ["read", "view_index_metadata"]
    }
  ]
}
```

## 8. Troubleshooting

### 8.1 Common Issues

#### Circuit Breaker:
- Parent circuit breaker triggered
- Tăng heap size hoặc giảm query complexity

#### Shard Allocation:
- Unassigned shards
- Check cluster routing allocation settings

#### Performance Issues:
- Monitor GC logs
- Check query patterns
- Optimize mappings và index settings

### 8.2 Log Analysis
```bash
# Important log locations
/var/log/elasticsearch/[cluster-name].log
/var/log/elasticsearch/[cluster-name]_index_indexing_slowlog.log
/var/log/elasticsearch/[cluster-name]_index_search_slowlog.log
```

## 9. Best Practices

### 9.1 Index Design
- Sử dụng time-based indices cho time-series data
- Proper shard sizing (20-50GB per shard)
- Avoid over-sharding

### 9.2 Query Optimization
- Use filters instead of queries khi có thể
- Avoid deep pagination
- Use appropriate analyzers

### 9.3 Monitoring
- Set up cluster monitoring
- Monitor key metrics: CPU, memory, disk I/O
- Use Kibana để visualization

### 9.4 Capacity Planning
- Plan cho data growth
- Monitor shard distribution
- Regular performance testing

## 10. Tổng Kết

Elasticsearch là một công cụ mạnh mẽ cho search và analytics, nhưng đòi hỏi hiểu biết sâu về architecture và configuration để tối ưu hóa performance. Key points để nhớ:

1. **Proper cluster sizing** và hardware selection
2. **Optimize mappings** và index settings
3. **Monitor cluster health** thường xuyên
4. **Plan for data lifecycle** với ILM
5. **Implement security** từ đầu
6. **Regular backup** và disaster recovery planning

Việc master các concepts và best practices này sẽ giúp bạn xây dựng và maintain một Elasticsearch cluster hiệu quả và ổn định.