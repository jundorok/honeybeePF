.PHONY: init plan apply destroy connect

SHELL := /bin/bash
.ONESHELL:

init:
	terraform init

plan:
	terraform plan

apply:
	terraform apply

destroy:
	terraform destroy

define KUBECONFIG_SCRIPT
set -e
echo "🔍 Fetching Cluster ID..."
CLUSTER_ID=$$(terraform output -raw cluster_id)
echo "✅ Cluster ID: $$CLUSTER_ID"

if [ -z "$$CLUSTER_ID" ]; then
  echo "❌ Error: No Cluster ID found. Run 'make apply' first."
  exit 1
fi

echo "🔄 Generating Kubeconfig..."
# Fetch the exact command from Terraform (handles region, ID, endpoint type)
KUBE_CMD=$$(terraform output -raw kubeconfig_command)
if [ -z "$$KUBE_CMD" ]; then
  echo "❌ Error: Could not get kubeconfig_command from Terraform."
  exit 1
fi

echo "Running: $$KUBE_CMD"
eval "$$KUBE_CMD"

echo "🔧 Patching Kubeconfig for Localhost Tunnel..."
kubectl config set-cluster $$(kubectl config view --minify -o jsonpath='{.clusters[0].name}') --server=https://127.0.0.1:6443 --insecure-skip-tls-verify=true

echo "✅ Kubeconfig updated! You can now run 'make connect'."
endef
export KUBECONFIG_SCRIPT

# Generates and patches Kubeconfig
kubeconfig:
	@/bin/bash -c "$$KUBECONFIG_SCRIPT"

define CONNECT_SCRIPT
set -e
echo "🔍 Reading Terraform outputs..."
BASTION_ID=$$(terraform output -raw bastion_id)
CLUSTER_IP=$$(terraform output -raw cluster_private_endpoint)

# Allow overriding keys via environment variables, default to standard locations
SSH_KEY_PUB="$${SSH_PUBLIC_KEY:-$$HOME/.ssh/id_rsa.pub}"
SSH_KEY_PRIV="$${SSH_PRIVATE_KEY:-$$HOME/.ssh/id_rsa}"

if [ -z "$$BASTION_ID" ] || [ -z "$$CLUSTER_IP" ]; then
  echo "❌ Error: Could not get BASTION_ID or CLUSTER_IP from Terraform."
  echo "   Did you run 'terraform apply'?"
  exit 1
fi

echo "✅ Bastion ID: $$BASTION_ID"
echo "✅ Cluster IP: $$CLUSTER_IP"

echo "🚀 Creating Bastion Session (TTL: 30 minutes)..."
# Use --query to extract ID directly, bypassing potential JSON formatting issues with keys
SESSION_ID=$$(oci bastion session create-port-forwarding \
  --bastion-id "$$BASTION_ID" \
  --target-private-ip "$$CLUSTER_IP" \
  --target-port 6443 \
  --display-name "auto-tunnel-$$(date +%s)" \
  --session-ttl 1800 \
  --ssh-public-key-file "$$SSH_KEY_PUB" \
  --query 'data.id' \
  --raw-output 2>&1)
EXIT_CODE=$$?

if [ $$EXIT_CODE -ne 0 ]; then
  echo "❌ OCI Command Failed (Exit Code: $$EXIT_CODE)"
  echo "Output:"
  echo "$$SESSION_ID"
  exit $$EXIT_CODE
fi

echo "✅ Session Created: $$SESSION_ID"

echo "⏳ Waiting for session to be active..."
while true; do
  # We suppress stderr here because OCI might return 404 for a split second after creation
  STATE=$$(oci bastion session get --session-id "$$SESSION_ID" --query "data.\"lifecycle-state\"" --raw-output 2>/dev/null || echo "PENDING")
  
  if [ "$$STATE" = "ACTIVE" ]; then
    echo "✅ Session is ACTIVE!"
    break
  fi
  echo "   Status: $$STATE..."
  sleep 2
done

echo "⏳ Waiting 10s for key propagation..."
sleep 10

# Get the SSH command
SSH_CMD=$$(oci bastion session get --session-id "$$SESSION_ID" --query "data.\"ssh-metadata\".command" --raw-output)

# Replace placeholders
SSH_CMD=$${SSH_CMD//<privateKey>/$$SSH_KEY_PRIV}
SSH_CMD=$${SSH_CMD//<localPort>/6443}

# Add verbose for debugging
SSH_CMD=$${SSH_CMD/ssh /ssh -v }

echo "****************************************************************"
echo "🔌 STARTING TUNNEL to https://127.0.0.1:6443"
echo "   Keep this terminal OPEN to maintain the connection."
echo "****************************************************************"
echo "Command: $$SSH_CMD"
echo ""

# Execute
eval "$$SSH_CMD"
endef
export CONNECT_SCRIPT

# Connects to the Private Cluster via Bastion
connect:
	@/bin/bash -c "$$CONNECT_SCRIPT"
