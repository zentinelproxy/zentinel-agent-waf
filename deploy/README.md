# Deployment

This directory contains deployment configurations for the Sentinel WAF Agent.

## Kubernetes Manifests

Raw Kubernetes manifests for deploying without Helm.

### Quick Start

```bash
# Apply all resources
kubectl apply -k kubernetes/

# Or apply individually
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/serviceaccount.yaml
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
kubectl apply -f kubernetes/poddisruptionbudget.yaml
```

### Customization with Kustomize

```bash
# Create an overlay
mkdir -p overlays/production
cat > overlays/production/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../kubernetes
patches:
  - patch: |-
      - op: replace
        path: /spec/replicas
        value: 5
    target:
      kind: Deployment
      name: sentinel-waf
EOF

# Apply the overlay
kubectl apply -k overlays/production/
```

## Helm Chart

A full-featured Helm chart with comprehensive configuration options.

### Installation

```bash
# Add the repository (when published)
helm repo add sentinel https://charts.sentinel.raskell.io
helm repo update

# Install from local chart
helm install sentinel-waf ./helm/sentinel-waf \
  --namespace sentinel \
  --create-namespace

# Install with custom values
helm install sentinel-waf ./helm/sentinel-waf \
  --namespace sentinel \
  --create-namespace \
  --set waf.paranoiaLevel=2 \
  --set waf.blockMode=true \
  --set replicaCount=3
```

### Configuration

See `helm/sentinel-waf/values.yaml` for all available options.

Common configurations:

```bash
# Production with higher paranoia
helm install sentinel-waf ./helm/sentinel-waf \
  --set waf.paranoiaLevel=2 \
  --set waf.scoring.blockThreshold=20 \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=3 \
  --set autoscaling.maxReplicas=10

# Detect-only mode for testing
helm install sentinel-waf ./helm/sentinel-waf \
  --set waf.blockMode=false \
  --set waf.paranoiaLevel=3

# With WebSocket inspection
helm install sentinel-waf ./helm/sentinel-waf \
  --set waf.websocket.enabled=true \
  --set waf.websocket.textFrames=true

# Minimal resources for development
helm install sentinel-waf ./helm/sentinel-waf \
  --set replicaCount=1 \
  --set resources.requests.cpu=50m \
  --set resources.requests.memory=32Mi \
  --set podDisruptionBudget.enabled=false
```

### Upgrade

```bash
helm upgrade sentinel-waf ./helm/sentinel-waf \
  --namespace sentinel \
  --set waf.paranoiaLevel=2
```

### Uninstall

```bash
helm uninstall sentinel-waf --namespace sentinel
```

## Resource Requirements

| Paranoia Level | Memory Request | Memory Limit |
|----------------|----------------|--------------|
| 1 | 32Mi | 64Mi |
| 2 | 48Mi | 96Mi |
| 3 | 64Mi | 128Mi |
| 4 | 96Mi | 192Mi |

## Health Checks

The WAF agent exposes health endpoints:

- **Liveness**: `GET /health` - Returns 200 if the agent is running
- **Readiness**: `GET /health` - Returns 200 when ready to accept traffic
- **Metrics**: `GET /metrics` - Prometheus metrics

## Integration with Sentinel Proxy

The WAF agent communicates with the Sentinel proxy via Unix domain socket. When deployed as a sidecar:

```yaml
# Example sidecar configuration
containers:
  - name: sentinel-proxy
    image: ghcr.io/raskell-io/sentinel:latest
    volumeMounts:
      - name: socket-dir
        mountPath: /var/run/sentinel
  - name: waf
    image: ghcr.io/raskell-io/sentinel-agent-waf:latest
    volumeMounts:
      - name: socket-dir
        mountPath: /var/run/sentinel
volumes:
  - name: socket-dir
    emptyDir: {}
```
