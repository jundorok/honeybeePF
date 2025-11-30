resource "oci_containerengine_cluster" "oke_cluster" {
  compartment_id     = var.compartment_ocid
  kubernetes_version = var.kubernetes_version
  name               = var.cluster_name
  vcn_id             = oci_core_vcn.oke_vcn.id

  endpoint_config {
    is_public_ip_enabled = false
    subnet_id            = oci_core_subnet.oke_api_subnet.id
  }

  options {
    add_ons {
      is_kubernetes_dashboard_enabled = false
      is_tiller_enabled               = false
    }
    service_lb_subnet_ids = [oci_core_subnet.oke_lb_subnet.id]
  }

  type = "BASIC_CLUSTER"
}
