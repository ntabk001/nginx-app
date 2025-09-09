```
Cách 1: Dùng kafka-dump-log

bash
kubectl exec -it kafka-0 -- \
  ./bin/kafka-dump-log.sh --cluster-metadata-decoder \
  --files /tmp/kafka-logs/__cluster_metadata-0/00000000000000000000.log 2>/dev/null | \
  grep -A5 -B5 "currentController"
Cách 2: Kiểm tra metrics

bash
kubectl exec -it kafka-0 -- \
  curl -s http://localhost:9999/metrics | \
  grep "controller_ActiveControllerCount" | \
  awk '{if ($2 == "1") print "This broker is controller"; else print "This broker is not controller"}'
  
  
#!/bin/bash
# check_controller.sh

POD=${1:-kafka-0}
echo "Checking controller status on $POD..."

# Method 1: Check metadata
echo "Method 1: Checking metadata snapshot..."
kubectl exec -it $POD -- \
  ./bin/kafka-dump-log.sh --cluster-metadata-decoder \
  --files /tmp/kafka-logs/__cluster_metadata-0/00000000000000000000.log 2>/dev/null | \
  grep -oP '"currentController".*?id: \K\d+' | head -1

# Method 2: Check metrics
echo "Method 2: Checking metrics..."
kubectl exec -it $POD -- \
  curl -s http://localhost:9999/metrics 2>/dev/null | \
  grep "kafka_controller_ActiveControllerCount" | \
  awk '{if ($2 == "1") print "Controller: YES"; else print "Controller: NO"}'

# Method 3: Check recent controller events
echo "Method 3: Checking controller events..."
kubectl exec -it $POD -- \
  grep -i "controller" /opt/kafka/logs/server.log 2>/dev/null | \
  grep -E "elected|resigned|changed" | tail -3


#!/bin/bash
# script check-controller.sh
POD=${1:-kafka-0}
echo "Checking controller on pod: $POD"
kubectl exec -it $POD -- grep -i "elected as controller" /opt/kafka/logs/server.log | tail -1
```
