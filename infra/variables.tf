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

variable "bastion_client_cidr" {
  default     = ["0.0.0.0/0"]
  description = "List of CIDR blocks allowed to connect to the Bastion Service"
  type        = list(string)
}

variable "bastion_max_session_ttl_in_seconds" {
  default     = 1800
  description = "The maximum amount of time (in seconds) that a bastion session can remain active."
  type        = number
}
