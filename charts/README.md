# HoneybeePF Monitoring Pipeline Installation Guide

## Architecture Overview

```
┌─────────────────┐     gRPC(4317)     ┌──────────────────────┐    scrape(8889)    ┌─────────────────┐
│   honeybeepf    │ ─────────────────► │  OTel Collector      │ ◄───────────────── │   Prometheus    │
│   (DaemonSet)   │                    │  (Deployment)        │                    │   (Server)      │
│                 │                    │                      │                    │                 │
│  eBPF metrics   │                    │  OTLP → Prometheus   │                    │  hbpf_* metrics │
│  collect & send │                    │  Exporter            │                    │  store & query  │
└─────────────────┘                    └──────────────────────┘                    └─────────────────┘
```

## Quick Start 

### 1. Add Required Helm Repositories

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
```

### 2. Update Helm Repository Dependencies

```bash
cd charts/honeybeepf-otel-collector
helm dependency update

cd ../honeybeepf-prometheus
helm dependency update
```

### 3. Create Namespace

```bash
kubectl create namespace monitoring
```

### 4. Sequential Installation

```bash
# 1. Install Prometheus (first, so it's ready to scrape)
helm install honeybeepf-prometheus ./charts/honeybeepf-prometheus \
  --namespace monitoring

# 2. Install OpenTelemetry Collector
helm install honeybeepf-otel-collector ./charts/honeybeepf-otel-collector \
  --namespace monitoring

# 3. Install honeybeepf DaemonSet
helm install honeybeepf ./charts/honeybeepf \
  --namespace monitoring
```

### 4. Verify Installation

```bash
# Check Pod status
kubectl get pods -n monitoring

# Check Services
kubectl get svc -n monitoring
```

## Configuration Structure

### Port Configuration

| Component | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| OTel Collector | 4317 | gRPC | OTLP metrics receiver |
| OTel Collector | 4318 | HTTP | OTLP HTTP receiver |
| OTel Collector | 8889 | HTTP | Prometheus exporter |

> **Note**: honeybeepf Agent does NOT expose metrics directly. All metrics flow through OTel Collector.

### Prometheus Scrape Configuration

This chart uses **annotation-based scraping** (NOT ServiceMonitor).
Prometheus scrapes the OTel Collector's prometheus exporter on port 8889.

> **Note**: If installing in a namespace other than `monitoring`, 
> update the scrape target in `honeybeepf-prometheus/values.yaml`.

### OTLP Endpoint Configuration

Priority:
1. **Helm values** (recommended)
2. Environment variables
3. Code default value

```yaml
# values.yaml
output:
  otlp:
    # FQDN format recommended
    endpoint: "honeybeepf-otel-collector-opentelemetry-collector.monitoring.svc.cluster.local:4317"
    protocol: "grpc"
```

## Best Practices Checklist

### ✅ Helm values.yaml

- [ ] Verify structure for direct install vs dependency install
- [ ] Check indentation/key names carefully
- [ ] Use FQDN format for endpoint
- [ ] Update namespace in endpoint if not using `monitoring`

### ✅ Rust Code

- [ ] Do NOT add `_total` suffix to Counter names (Prometheus adds it automatically)
- [ ] Log OTLP endpoint at startup
- [ ] Implement graceful shutdown

## Troubleshooting

### 1. Targets Not Visible in Prometheus

```bash
# Check Endpoints
kubectl get endpoints -n monitoring

# Check Prometheus targets page
kubectl port-forward svc/honeybeepf-prometheus-server -n monitoring 9090:80
# Open http://localhost:9090/targets in browser
```

### 2. Metrics Not Being Collected

```bash
# Check OTel Collector logs
kubectl logs -n monitoring -l app.kubernetes.io/name=opentelemetry-collector

# Check honeybeepf logs (verify OTLP endpoint output)
kubectl logs -n monitoring -l app.kubernetes.io/name=honeybeepf

# Check OTel Collector metrics directly
kubectl port-forward svc/honeybeepf-otel-collector-opentelemetry-collector -n monitoring 8889:8889
curl http://localhost:8889/metrics | grep hbpf_
```

### 3. Label Mismatch Check

```bash
# Check Service labels
kubectl get svc -n monitoring -o jsonpath='{.items[*].metadata.labels}'

# Check ServiceMonitor selector
kubectl get servicemonitor -n monitoring -o jsonpath='{.items[*].spec.selector}'
```

## Metrics List

| Metric Name | Type | Description |
|-------------|------|-------------|
| `honeybeepf_hbpf_block_io_events_total` | Counter | Number of Block I/O events |
| `honeybeepf_hbpf_block_io_bytes_total` | Counter | Total Block I/O bytes |
| `honeybeepf_hbpf_block_io_latency_ns` | Histogram | Block I/O latency (nanoseconds) |
| `honeybeepf_hbpf_network_latency_ns` | Histogram | Network latency (nanoseconds) |
| `honeybeepf_hbpf_gpu_open_events_total` | Counter | Number of GPU device open events |
| `honeybeepf_hbpf_active_probes` | Gauge | Number of currently active eBPF probes |

## Prometheus Query Examples

```promql
# Block I/O events rate (per second)
rate(honeybeepf_hbpf_block_io_events_total[5m])

# Block I/O throughput (bytes/sec)
rate(honeybeepf_hbpf_block_io_bytes_total[5m])

# GPU open events by device
sum by (device) (honeybeepf_hbpf_gpu_open_events_total)

# Active probes list
sum by (probe) (honeybeepf_hbpf_active_probes)
```

## Custom Configuration Examples

### Change OTel Collector Endpoint

```yaml
# charts/honeybeepf/values.yaml
output:
  otlp:
    endpoint: "my-custom-collector.default.svc.cluster.local:4317"
```

### Enable Specific Probes Only

```yaml
# charts/honeybeepf/values.yaml
builtinProbes:
  block_io:
    enabled: true
  network_latency:
    enabled: false
  gpu_open:
    enabled: true
  interval: 1000
```
