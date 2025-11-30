# OCI Free Tier Kubernetes Infrastructure

This directory contains Terraform configuration to provision an Oracle Kubernetes Engine (OKE) cluster that fits entirely within the **OCI Always Free Tier** limits.

## Resources Created

*   **VCN**: Virtual Cloud Network with Public and Private subnets.
*   **OKE Cluster**: "Basic" type cluster (Free).
*   **Node Pool**: 2x Ampere A1 instances (2 OCPUs, 12GB RAM each).

## Prerequisites

1.  **OCI Account**: You need an active Oracle Cloud account.
2.  **OCI CLI**: Installed and configured on your machine.
    *   Install: `brew install oci-cli` (macOS) or see [official docs](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm).
    *   Configure: Run `oci setup config` and follow the prompts.
3.  **Terraform**: Installed on your machine.

## How to Use

1.  **Initialize Terraform**:
    ```bash
    terraform init
    ```

2.  **Configure Environment Variables**:
    Instead of hardcoding values, we use environment variables. Run these commands in your terminal:

    ```bash
    # Set the Compartment ID (usually your Tenancy OCID for personal accounts)
    export TF_VAR_compartment_ocid="<your-tenancy-ocid>"

    # Set the SSH Public Key (for worker node access)
    export TF_VAR_ssh_public_key=$(cat ~/.ssh/id_rsa.pub)
    ```

3.  **Plan and Apply**:
    ```bash
    terraform plan
    terraform apply
    ```

4.  **Access Cluster**:
    After the apply finishes, Terraform will output a command. Run it to generate your `kubeconfig`:
    ```bash
    oci ce cluster create-kubeconfig ...
    ```

## Cleanup

To remove all resources created by this Terraform configuration:

```bash
terraform destroy
```

Type `yes` when prompted. This will delete the Cluster, Node Pool, VCN, and all associated networking resources.

## Troubleshooting

*   **Out of Host Capacity**: If you see `500-InternalError` or `Out of host capacity`, it means the region is temporarily out of free Ampere A1 instances. Wait a while and try running `terraform apply` again.
