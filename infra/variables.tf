variable "compartment_ocid" {}

variable "ssh_public_key" {
  description = "SSH public key for worker nodes"
  type        = string
}

variable "name_prefix" {
  default     = "oke"
  description = "Prefix for resource names"
}

variable "cluster_name" {
  default = "free-tier-oke"
}

variable "kubernetes_version" {
  default = "v1.34.1"
}

variable "node_pool_size" {
  default = 2
}

variable "node_ocpus" {
  default = 2
}

variable "node_memory_gbs" {
  default = 12
}

variable "node_shape" {
  default = "VM.Standard.A1.Flex"
}
