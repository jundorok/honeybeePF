resource "oci_bastion_bastion" "k8s_bastion" {
  name             = "k8s-bastion-service"
  bastion_type     = "STANDARD"
  compartment_id   = var.compartment_ocid
  target_subnet_id = oci_core_subnet.oke_api_subnet.id
  
  client_cidr_block_allow_list = var.bastion_client_cidr
  max_session_ttl_in_seconds   = var.bastion_max_session_ttl_in_seconds
}
