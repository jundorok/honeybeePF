output "cluster_id" {
  value = oci_containerengine_cluster.oke_cluster.id
}

output "tunnel_setup_command" {
  value = "kubectl config set-cluster $(kubectl config view --minify -o jsonpath='{.clusters[0].name}') --server=https://127.0.0.1:6443 --insecure-skip-tls-verify=true"
}

output "bastion_id" {
  value = oci_bastion_bastion.k8s_bastion.id
}

output "cluster_private_endpoint" {
  # This extracts the IP (e.g., 10.0.0.252:6443) and removes the port to get just the IP
  value = split(":", oci_containerengine_cluster.oke_cluster.endpoints[0].private_endpoint)[0]
}

output "kubeconfig_command" {
  value = "oci ce cluster create-kubeconfig --cluster-id ${oci_containerengine_cluster.oke_cluster.id} --file $HOME/.kube/config --token-version 2.0.0 --kube-endpoint PRIVATE_ENDPOINT"
}
