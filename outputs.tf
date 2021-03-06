output "id" {
  description = "List of IDs of instances"
  value       = aws_instance.ec2.*.id
}

output "arn" {
  description = "List of ARNs of instances"
  value       = aws_instance.ec2.*.arn
}

output "availability_zone" {
  description = "List of availability zones of instances"
  value       = aws_instance.ec2.*.availability_zone
}

output "placement_group" {
  description = "List of placement groups of instances"
  value       = aws_instance.ec2.*.placement_group
}

output "key_name" {
  description = "List of key names of instances"
  value       = aws_instance.ec2.*.key_name
}

output "password_data" {
  description = "List of Base-64 encoded encrypted password data for the instance"
  value       = aws_instance.ec2.*.password_data
}

output "public_dns" {
  description = "List of public DNS names assigned to the instances. For EC2-VPC, this is only available if you've enabled DNS hostnames for your VPC"
  value       = aws_instance.ec2.*.public_dns
}

output "public_ip" {
  description = "List of public IP addresses assigned to the instances, if applicable"
  value       = aws_instance.ec2.*.public_ip
}

output "ipv6_addresses" {
  description = "List of assigned IPv6 addresses of instances"
  value       = aws_instance.ec2.*.ipv6_addresses
}

output "primary_network_interface_id" {
  description = "List of IDs of the primary network interface of instances"
  value       = aws_instance.ec2.*.primary_network_interface_id
}

output "private_dns" {
  description = "List of private DNS names assigned to the instances. Can only be used inside the Amazon EC2, and only available if you've enabled DNS hostnames for your VPC"
  value       = aws_instance.ec2.*.private_dns
}

output "private_ip" {
  description = "List of private IP addresses assigned to the instances"
  value       = aws_instance.ec2.*.private_ip
}

output "security_groups" {
  description = "List of associated security groups of instances"
  value       = aws_instance.ec2.*.security_groups
}

output "vpc_security_group_ids" {
  description = "List of associated security groups of instances, if running in non-default VPC"
  value       = aws_instance.ec2.*.vpc_security_group_ids
}

output "subnet_id" {
  description = "List of IDs of VPC subnets of instances"
  value       = aws_instance.ec2.*.subnet_id
}

output "credit_specification" {
  description = "List of credit specification of instances"
  value       = aws_instance.ec2.*.credit_specification
}

output "metadata_options" {
  description = "List of metadata options of instances"
  value       = aws_instance.ec2.*.metadata_options
}

output "instance_state" {
  description = "List of instance states of instances"
  value       = aws_instance.ec2.*.instance_state
}

output "root_block_device_volume_ids" {
  description = "List of volume IDs of root block devices of instances"
  value       = [for device in aws_instance.ec2.*.root_block_device : device.*.volume_id]
}

output "ebs_block_device_volume_ids" {
  description = "List of volume IDs of EBS block devices of instances"
  value       = [for device in aws_instance.ec2.*.ebs_block_device : device.*.volume_id]
}

output "tags" {
  description = "List of tags of instances"
  value       = aws_instance.ec2.*.tags
}

output "volume_tags" {
  description = "List of tags of volumes of instances"
  value       = aws_instance.ec2.*.volume_tags
}

output "instance_count" {
  description = "Number of instances to launch specified as argument to this module"
  value       = var.instance_count
}

###############
# Extra outputs
###############
output "security_group_id_ec2" {
  description = "ID of security group to use for the application server"
  value = aws_security_group.ec2.id
}

output "security_group_id_database_from_ec2" {
  description = "ID of security group to use for the RDS that allows incoming connections from the application server"
  value = aws_security_group.ec2-to-database.*.id
}