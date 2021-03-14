variable "name" {
  description = "Name to be used on all resources as prefix"
  type        = string
}

variable "instance_count" {
  description = "Number of instances to launch"
  type        = number
  default     = 1
}

variable "ami" {
  description = "ID of AMI to use for the instance"
  type        = map
}

variable "placement_group" {
  description = "The Placement Group to start the instance in"
  type        = string
  default     = ""
}

variable "get_password_data" {
  description = "If true, wait for password data to become available and retrieve it."
  type        = bool
  default     = false
}

variable "tenancy" {
  description = "The tenancy of the instance (if the instance is running in a VPC). Available values: default, dedicated, host."
  type        = string
  default     = "default"
}

variable "ebs_optimized" {
  description = "If true, the launched EC2 instance will be EBS-optimized"
  type        = bool
  default     = false
}

variable "disable_api_termination" {
  description = "If true, enables EC2 Instance Termination Protection"
  type        = bool
  default     = false
}

variable "instance_initiated_shutdown_behavior" {
  description = "Shutdown behavior for the instance" # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#Using_ChangingInstanceInitiatedShutdownBehavior
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "The type of instance to start"
  type        = string
}

variable "monitoring" {
  description = "If true, the launched EC2 instance will have detailed monitoring enabled"
  type        = bool
  default     = false
}

variable "vpc_security_group_ids" {
  description = "A list of security group IDs to associate with"
  type        = list(string)
  default     = null
}

variable "subnet_id" {
  description = "The VPC Subnet ID to launch in"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "A list of VPC Subnet IDs to launch in"
  type        = list(string)
  default     = []
}

variable "associate_public_ip_address" {
  description = "If true, the EC2 instance will have associated public IP address"
  type        = bool
  default     = null
}

variable "private_ip" {
  description = "Private IP address to associate with the instance in a VPC"
  type        = string
  default     = null
}

variable "private_ips" {
  description = "A list of private IP address to associate with the instance in a VPC. Should match the number of instances."
  type        = list(string)
  default     = []
}

variable "source_dest_check" {
  description = "Controls if traffic is routed to the instance when the destination address does not match the instance. Used for NAT or VPNs."
  type        = bool
  default     = true
}

variable "user_data" {
  description = "The user data to provide when launching the instance. Do not pass gzip-compressed data via this argument; see user_data_base64 instead."
  type        = string
  default     = null
}

variable "user_data_base64" {
  description = "Can be used instead of user_data to pass base64-encoded binary data directly."
  type        = string
  default     = null
}

variable "iam_instance_profile" {
  description = "The IAM Instance Profile to launch the instance with. Specified as the name of the Instance Profile."
  type        = string
  default     = ""
}

variable "ipv6_address_count" {
  description = "A number of IPv6 addresses to associate with the primary network interface. Amazon EC2 chooses the IPv6 addresses from the range of your subnet."
  type        = number
  default     = null
}

variable "ipv6_addresses" {
  description = "Specify one or more IPv6 addresses from the range of the subnet to associate with the primary network interface"
  type        = list(string)
  default     = null
}

variable "tags" {
  description = "A mapping of tags to assign to the resource"
  type        = map(string)
  default     = {}
}

variable "volume_tags" {
  description = "A mapping of tags to assign to the devices created by the instance at launch time"
  type        = map(string)
  default     = {}
}

variable "root_block_device" {
  description = "Customize details about the root block device of the instance. See Block Devices below for details"
  type        = list(map(string))
  default     = []
}

variable "ebs_block_device" {
  description = "Additional EBS block devices to attach to the instance"
  type        = list(map(string))
  default     = []
}

variable "ephemeral_block_device" {
  description = "Customize Ephemeral (also known as Instance Store) volumes on the instance"
  type        = list(map(string))
  default     = []
}

variable "network_interface" {
  description = "Customize network interfaces to be attached at instance boot time"
  type        = list(map(string))
  default     = []
}

variable "cpu_credits" {
  description = "The credit option for CPU usage (unlimited or standard)"
  type        = string
  default     = "standard"
}

variable "metadata_options" {
  description = "Customize the metadata options of the instance"
  type        = map(string)
  default     = {}
}

variable "use_num_suffix" {
  description = "Always append numerical suffix to instance name, even if instance_count is 1"
  type        = bool
  default     = false
}

variable "num_suffix_format" {
  description = "Numerical suffix format used as the volume and EC2 instance name suffix"
  type        = string
  default     = "-%d"
}

variable "region" {
  description = "Name of region"
  type        = string
}

variable "vpc_id" {
  description = "String of vpc id"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC cidr for security group rules"
  type        = string
  default     = "10.0.0.0/16"
}

variable "ssh_pubkey" {
  description = "SSH Public Key"
  type        = string
}

variable "eip_alloc_ids" {
  description = "List of Elastic IP associations for the EC2 instance"
  type        = list(string)
  default     = null
}

variable "enable_any_egress_to_vpc" {
  description = "Enable any egress traffic from EC2 instance to VPC"
  type        = bool
  default     = true
}

variable "sg_rule_rds_port" {
  description = "Port for ingress security group rules to RDS"
  type        = number
  default     = null
}

variable "sg_rules_egress_cidr_map" {
  description = "Map of security group rules for egress communication of cidr"
  type        = map
  default     = {}
}

variable "sg_rules_ingress_cidr_map" {
  description = "Map of security group rules for ingress communication of cidr"
  type        = map
  default     = {}
}

variable "sg_rules_egress_source_sg_map" {
  description = "Map of security group rules for egress communication of security group source ids"
  type        = map
  default     = {}
}

variable "sg_rules_ingress_source_sg_map" {
  description = "Map of security group rules for ingress communication of security group source ids"
  type        = map
  default     = {}
}

variable "cloudwatch_sns_topic_arn" {
  description = "SNS Topic ARN for CloudWatch alarms"
  type        = string
  default     = null
}

variable "cloudwatch_autorecover_enabled" {
  description = "Enable or disable CloudWatch alarm EC2 autorecover"
  type        = bool
  default     = true
}

variable "cloudwatch_cpu_utilization_enabled" {
  description = "Enable or disable CloudWatch alarm CPU utilization"
  type        = bool
  default     = false
}

variable "backup_enabled" {
  description = "Enable or disable AWS Backup"
  type        = bool
  default     = false
}

variable "backup_tags" {
  description = "A mapping of backup tags to assign to the resource"
  type        = map(string)
  default     = {}
}

variable "backup_vault_kms_key_arn" {
  description = "AWS Backup vault KMS key arn"
  type        = string
  default     = null
}

variable "backup_plan_schedule" {
  description = "AWS Backup plan schedule"
  type        = string
  default     = "cron(0 3 * * ? *)"
}

variable "backup_plan_windows_vss" {
  description = "AWS Backup plan Windows VSS feature"
  type        = string
  default     = "disabled"
}

variable "backup_plan_tag_key" {
  description = "AWS Backup selection tag key"
  type        = string
  default     = "Backup"
}

variable "backup_plan_tag_value" {
  description = "AWS Backup selection tag value"
  type        = string
  default     = "enabled"
}