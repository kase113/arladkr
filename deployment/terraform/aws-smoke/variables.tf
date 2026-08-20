variable "aws_profile" {
  description = "AWS CLI profile used by Terraform."
  type        = string
  default     = "arladkr-sso"
}

variable "aws_region" {
  description = "AWS region for the single-region smoke experiment."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone_id" {
  description = "Stable physical AZ identifier for all smoke nodes."
  type        = string
  default     = "use1-az5"
}

variable "vpc_cidr" {
  description = "VPC CIDR for this regional experiment stack."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "node_subnet_cidr" {
  description = "Node subnet CIDR. Keep the existing /24 for smoke; pass a /23 or larger for n=256."
  type        = string
  default     = "10.42.1.0/24"

  validation {
    condition     = can(cidrnetmask(var.node_subnet_cidr))
    error_message = "node_subnet_cidr must be a valid IPv4 CIDR."
  }
}

variable "node_private_ip_offset" {
  description = "First usable host offset assigned to NodeSlot zero in this subnet."
  type        = number
  default     = 10

  validation {
    condition     = var.node_private_ip_offset >= 5 && var.node_private_ip_offset == floor(var.node_private_ip_offset)
    error_message = "node_private_ip_offset must be an integer of at least 5."
  }
}

variable "node_slot_offset" {
  description = "Global NodeSlot offset; use a distinct range for each regional stack."
  type        = number
  default     = 0

  validation {
    condition     = var.node_slot_offset >= 0 && var.node_slot_offset == floor(var.node_slot_offset)
    error_message = "node_slot_offset must be a non-negative integer."
  }
}

variable "instance_type" {
  description = "Homogeneous benchmark instance type."
  type        = string
  default     = "c7g.xlarge"
}

variable "ami_id" {
  description = "Pinned benchmark AMI. Leave empty to use the current Amazon Linux 2023 ARM64 base image."
  type        = string
  default     = ""
}

variable "instance_count" {
  description = "One EC2 instance per old-committee node."
  type        = number
  default     = 0

  validation {
    condition     = var.instance_count >= 0 && var.instance_count <= 256
    error_message = "instance_count must be between 0 and 256."
  }
}

variable "protocol_suite" {
  description = "Canonical discovery tag value."
  type        = string
  default     = "rla"
}

variable "experiment_group" {
  description = "Unique tag used to discover and destroy only this experiment."
  type        = string
  default     = "smoke-n10-use1-20260817-142937"
}

variable "root_volume_gb" {
  description = "Per-node gp3 root volume size."
  type        = number
  default     = 30
}

variable "enable_public_protocol" {
  description = "Allow protocol TCP over public IPv4 from this fleet and explicit peer CIDRs."
  type        = bool
  default     = false
}

variable "protocol_public_port_from" {
  description = "First public protocol TCP port."
  type        = number
  default     = 30000

  validation {
    condition     = var.protocol_public_port_from >= 1 && var.protocol_public_port_from <= 65535
    error_message = "protocol_public_port_from must be between 1 and 65535."
  }
}

variable "protocol_public_port_to" {
  description = "Last public protocol TCP port, including derived protocol namespace ports."
  type        = number
  default     = 60000

  validation {
    condition     = var.protocol_public_port_to >= var.protocol_public_port_from && var.protocol_public_port_to <= 65535
    error_message = "protocol_public_port_to must be between 1 and 65535."
  }
}

variable "protocol_public_peer_cidrs" {
  description = "Additional public peer /32 CIDRs, normally from other regional stacks. Exclude this stack's own public IPs."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.protocol_public_peer_cidrs :
      can(cidrnetmask(cidr)) && can(regex("/32$", cidr))
    ])
    error_message = "protocol_public_peer_cidrs must contain IPv4 /32 CIDRs only."
  }
}

variable "protocol_public_world_ingress" {
  description = "Replace per-node /32 protocol rules with one temporary CIDR rule when a large fleet would exceed the SG rule quota."
  type        = bool
  default     = false
}

variable "protocol_public_ingress_cidr" {
  description = "CIDR used by protocol_public_world_ingress. The protocol ports carry authenticated experiment traffic only."
  type        = string
  default     = "0.0.0.0/0"

  validation {
    condition     = can(cidrnetmask(var.protocol_public_ingress_cidr))
    error_message = "protocol_public_ingress_cidr must be a valid IPv4 CIDR."
  }
}
