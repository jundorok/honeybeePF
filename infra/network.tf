resource "oci_core_vcn" "oke_vcn" {
  cidr_block     = "10.0.0.0/16"
  compartment_id = var.compartment_ocid
  display_name   = "${var.name_prefix}-vcn"
  dns_label      = "${var.name_prefix}vcn"
}

resource "oci_core_internet_gateway" "oke_ig" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.name_prefix}-internet-gateway"
  vcn_id         = oci_core_vcn.oke_vcn.id
}

resource "oci_core_nat_gateway" "oke_nat" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.name_prefix}-nat-gateway"
  vcn_id         = oci_core_vcn.oke_vcn.id
}

resource "oci_core_service_gateway" "oke_sg" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.name_prefix}-service-gateway"
  vcn_id         = oci_core_vcn.oke_vcn.id
  services {
    service_id = data.oci_core_services.all_services.services[0].id
  }
}

data "oci_core_services" "all_services" {
  filter {
    name   = "name"
    values = ["All .* Services In Oracle Services Network"]
    regex  = true
  }
}

resource "oci_core_route_table" "public_rt" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.name_prefix}-public-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.oke_ig.id
  }
}

resource "oci_core_route_table" "private_rt" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.name_prefix}-private-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.oke_nat.id
  }

  route_rules {
    destination       = data.oci_core_services.all_services.services[0].cidr_block
    destination_type  = "SERVICE_CIDR_BLOCK"
    network_entity_id = oci_core_service_gateway.oke_sg.id
  }
}

resource "oci_core_security_list" "oke_api_sl" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.name_prefix}-api-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    protocol = "6" # TCP
    source   = "0.0.0.0/0"
    tcp_options {
      max = 6443
      min = 6443
    }
  }
  
  ingress_security_rules {
    protocol = "6" # TCP
    source   = "10.0.0.0/16"
  }
}

resource "oci_core_security_list" "oke_node_sl" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.name_prefix}-node-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    protocol = "all"
    source   = "10.0.0.0/16"
  }
}

resource "oci_core_subnet" "oke_api_subnet" {
  cidr_block        = "10.0.0.0/24"
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.oke_vcn.id
  display_name      = "${var.name_prefix}-api-subnet"
  route_table_id    = oci_core_route_table.public_rt.id
  security_list_ids = [oci_core_security_list.oke_api_sl.id]
}

resource "oci_core_subnet" "oke_node_subnet" {
  cidr_block                 = "10.0.1.0/24"
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.oke_vcn.id
  display_name               = "${var.name_prefix}-node-subnet"
  route_table_id             = oci_core_route_table.private_rt.id
  security_list_ids          = [oci_core_security_list.oke_node_sl.id]
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_subnet" "oke_lb_subnet" {
  cidr_block        = "10.0.2.0/24"
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.oke_vcn.id
  display_name      = "${var.name_prefix}-lb-subnet"
  route_table_id    = oci_core_route_table.public_rt.id
  security_list_ids = [oci_core_security_list.oke_api_sl.id] # Reusing API SL for simplicity, adjust for LB
}
