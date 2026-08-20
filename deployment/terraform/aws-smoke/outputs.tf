output "experiment_group" {
  value = var.experiment_group
}

output "availability_zone_id" {
  value = var.availability_zone_id
}

output "availability_zone" {
  value = aws_subnet.nodes.availability_zone
}

output "ami_id" {
  value = var.ami_id != "" ? var.ami_id : nonsensitive(data.aws_ssm_parameter.al2023_arm64.value)
}

output "instance_ids" {
  value = aws_instance.node[*].id
}

output "private_ips" {
  value = aws_instance.node[*].private_ip
}

output "public_ips" {
  value = aws_instance.node[*].public_ip
}

output "local_public_cidrs" {
  value = [for instance in aws_instance.node : "${instance.public_ip}/32"]
}

output "node_roster" {
  value = [
    for index, instance in aws_instance.node : {
      node_slot   = index + var.node_slot_offset
      instance_id = instance.id
      private_ip  = instance.private_ip
      public_ip   = instance.public_ip
      region      = var.aws_region
      az          = instance.availability_zone
    }
  ]
}

output "security_group_id" {
  value = aws_security_group.nodes.id
}
