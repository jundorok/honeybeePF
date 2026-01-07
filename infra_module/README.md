# OKE Private Cluster Access via Bastion

Access Oracle Kubernetes Engine (OKE) clusters in private subnets through OCI Bastion service.

## Prerequisites

- OCI CLI installed and configured (`~/.oci/config`)
- SSH key pair (`~/.ssh/id_rsa` and `~/.ssh/id_rsa.pub`)
- `kubectl` installed
- IAM permissions (see [Access Requirements](#access-requirements))

## Per-user Terraform environments

This repo supports one isolated Terraform environment per developer under `infra_module/envs/<your-name>`.

- Use `infra_module/envs/sample/` as a template.
- A real example exists at `infra_module/envs/jun/`.

### Create your environment

1. Copy the template and switch into it:

```bash
cp -R infra_module/envs/sample infra_module/envs/<your-name>
cd infra_module/envs/<your-name>
```

2. Edit `dev.tfvars` to customize non‑secret settings (names, sizes, CIDRs). Secrets go via env vars, not the file.

3. Export the required variables in your shell (zsh):

```bash
# OCI IDs (do not commit these)
export TF_VAR_compartment_ocid="<your-compartment-ocid>"
export TF_VAR_tenancy_ocid="<your-tenancy-ocid>"

# Public key for node access
export TF_VAR_ssh_public_key="$(cat ~/.ssh/id_rsa.pub)"

# Allow your current public IP to reach Bastion
export TF_VAR_bastion_client_cidr_list="[\"$(curl -s ifconfig.me)/32\"]"
```

Notes:
- The OCI provider reads credentials from `~/.oci/config`. Make sure `oci` CLI works before running Terraform.
- Keep `dev.tfvars` focused on non‑secret config. Env vars override variable values at runtime.

### Plan and apply

From your env directory (`infra_module/envs/<your-name>`):

```bash
terraform init
terraform plan -var-file=dev.tfvars
terraform apply -var-file=dev.tfvars
```

On success, Terraform will output:
- `cluster_id` — your OKE cluster OCID
- `kubeconfig_command` — a handy command to generate kubeconfig

You can then follow the Bastion tunnel steps below to access the private cluster API.

### Destroy (cleanup)

```bash
terraform destroy -var-file=dev.tfvars
```

### Variable reference

The stack expects these key variables (set via env or `dev.tfvars`):
- `compartment_ocid` (string)
- `tenancy_ocid` (string)
- `bastion_client_cidr_list` (list(string))
- `ssh_public_key` (string)
- `name_prefix`, `cluster_name`, `kubernetes_version`
- Node pool: `node_pool_size`, `node_shape`, `node_ocpus`, `node_memory_gbs`
- Networking: `vcn_cidr`, `api_subnet_cidr`, `node_subnet_cidr`

## Quick Start

### 1. Create Bastion Session and SSH Tunnel

Run the setup script:

```bash
./bastion-tunnel.sh
```

The script will:
1. List available bastions → select one
2. List active OKE clusters → select one
3. Create a port-forwarding session
4. Start SSH tunnel on `localhost:6443`

**Keep this terminal open** - the tunnel must stay running.

### 2. Configure kubectl

In a new terminal:

```bash
# Generate kubeconfig pointing through the tunnel
oci ce cluster create-kubeconfig \
  --cluster-id <your-cluster-ocid> \
  --file ~/.kube/config \
  --token-version 2.0.0 \
  --kube-endpoint PRIVATE_ENDPOINT

# Update cluster endpoint to use the tunnel
kubectl config set-cluster cluster-<suffix> \
  --server=https://127.0.0.1:6443 \
  --insecure-skip-tls-verify=true

# Verify
kubectl get ns
```

## Setup Script

Save as `bastion-tunnel.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="$HOME/.oci/config"
SSH_PUB_KEY="$HOME/.ssh/id_rsa.pub"
SSH_PRIVATE_KEY="$HOME/.ssh/id_rsa"
SESSION_TTL=3600
K8S_API_PORT=6443

error() {
  echo "❌ $1" >&2
  exit 1
}

check_cmd() {
  command -v "$1" >/dev/null 2>&1 || error "Required command '$1' not found"
}

check_cmd oci
check_cmd grep

[[ -f "$CONFIG_FILE" ]] || error "OCI config not found at $CONFIG_FILE"
[[ -f "$SSH_PUB_KEY" ]] || error "SSH public key not found at $SSH_PUB_KEY"
[[ -f "$SSH_PRIVATE_KEY" ]] || error "SSH private key not found at $SSH_PRIVATE_KEY"

COMPARTMENT_ID=$(grep '^tenancy=' "$CONFIG_FILE" | cut -d= -f2)
[[ -n "$COMPARTMENT_ID" ]] || error "Failed to read compartment ID"

echo "📦 Compartment ID: $COMPARTMENT_ID"
echo

echo "🔐 Available Bastions:"
oci bastion bastion list \
  --compartment-id "$COMPARTMENT_ID" \
  --query 'data[].{name:name,id:id}' \
  --output table

echo
read -rp "Enter Bastion ID: " BASTION_ID
[[ -n "$BASTION_ID" ]] || error "Bastion ID is required"

echo "🔎 Verifying Bastion..."
oci bastion bastion get --bastion-id "$BASTION_ID" >/dev/null

echo
echo "☸️  Active OKE Clusters:"
oci ce cluster list \
  --compartment-id "$COMPARTMENT_ID" \
  --all \
  --query 'data[?"lifecycle-state"==`ACTIVE`].{name:name,id:id}' \
  --output table

echo
read -rp "Enter Cluster ID: " CLUSTER_ID
[[ -n "$CLUSTER_ID" ]] || error "Cluster ID is required"

echo
echo "🌐 Fetching Kubernetes API private IP..."
oci ce cluster get \
  --cluster-id "$CLUSTER_ID" \
  --query 'data.endpoints' \
  --raw-output

echo
read -rp "Enter K8S Private IP (e.g., 10.0.0.92): " K8S_PRIVATE_IP
[[ -n "$K8S_PRIVATE_IP" ]] || error "K8S_PRIVATE_IP is required"

echo
echo "🚀 Creating Bastion Port Forwarding Session..."
SESSION=$(oci bastion session create-port-forwarding \
  --bastion-id "$BASTION_ID" \
  --target-private-ip "$K8S_PRIVATE_IP" \
  --target-port "$K8S_API_PORT" \
  --session-ttl "$SESSION_TTL" \
  --ssh-public-key-file "$SSH_PUB_KEY" \
  --query 'data.id' \
  --raw-output)

echo "✅ Session created: $SESSION"
echo "⏳ Session TTL: ${SESSION_TTL}s"

echo "⏳ Waiting for session to become ACTIVE..."
for i in {1..40}; do
  STATE=$(oci bastion session get --session-id "$SESSION" \
    --query 'data."lifecycle-state"' --raw-output || true)
  [[ "$STATE" == "ACTIVE" ]] && break
  sleep 3
done
[[ "$STATE" != "ACTIVE" ]] && error "Session did not become ACTIVE (state: $STATE)"

echo "🔌 Starting SSH tunnel (keep this open)..."
SSH_CMD=$(oci bastion session get --session-id "$SESSION" \
  --query 'data."ssh-metadata".command' --raw-output)

SSH_CMD=${SSH_CMD//<privateKey>/$SSH_PRIVATE_KEY}
SSH_CMD=${SSH_CMD//<localPort>/6443}

echo "$SSH_CMD"
eval "$SSH_CMD"
```

Make it executable:

```bash
chmod +x bastion-tunnel.sh
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `connection to localhost:8080 refused` | kubectl not using your kubeconfig | Set `export KUBECONFIG=~/.kube/config` and select correct context |
| `server has asked for credentials` | OCI token auth not configured | Re-run `oci ce cluster create-kubeconfig` command |
| `dial tcp 10.x.x.x:6443: network unreachable` | kubectl pointing to private IP, not tunnel | Run `kubectl config set-cluster <name> --server=https://127.0.0.1:6443` |
| `certificate signed by unknown authority` | TLS cert doesn't match localhost | Add `--insecure-skip-tls-verify=true` to cluster config |
| Username/password prompt | User not set in kubeconfig context | Check `kubectl config view` and ensure context has correct user |

### Verify Configuration

```bash
# Check current context
kubectl config current-context

# View full config
kubectl config view

# Test OCI token generation
oci ce cluster generate-token \
  --cluster-id <cluster-ocid> \
  --region ap-singapore-1
```

## Access Requirements

Your OCI user needs these IAM policies:

```
Allow group <your-group> to inspect bastions in compartment <compartment>
Allow group <your-group> to manage bastion-sessions in compartment <compartment>
Allow group <your-group> to use clusters in compartment <compartment>
```

## Architecture

```
┌──────────────┐      SSH Tunnel       ┌─────────────┐      ┌──────────────┐
│   Your Mac   │ ───────────────────▶  │   Bastion   │ ───▶ │  OKE API     │
│ localhost:6443                       │  (Public)   │      │  10.0.0.92   │
└──────────────┘                       └─────────────┘      └──────────────┘
       │                                                           │
       │                                                           │
       ▼                                                           ▼
   kubectl ──── OCI Token Auth ──────────────────────────────▶ Kubernetes
```

## Tips

- Sessions expire after TTL (default: 1 hour). Re-run the script to create a new session.
- You can have multiple kubeconfig contexts for different clusters.
- To suppress OCI warnings, set `export SUPPRESS_LABEL_WARNING=True`.