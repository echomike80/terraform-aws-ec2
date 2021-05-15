##############
# Data sources
##############
data "aws_caller_identity" "current" {
}

########
# Locals
########
locals {
  is_t_instance_type = replace(var.instance_type, "/^t(2|3|3a){1}\\..*$/", "1") == "1" ? true : false
}

#################
# Security Groups
#################
resource "aws_security_group" "ec2" {
  name        = var.name
  description = "Rules for ${var.name}"
  vpc_id      = var.vpc_id

  tags = merge(
    {
      Name = var.name
    },
    var.tags,
  )
}

resource "aws_security_group_rule" "in-each-port-ec2-from-cidr" {
  for_each                  = var.sg_rules_ingress_cidr_map
  type                      = "ingress"
  from_port                 = each.value.port
  to_port                   = each.value.port
  protocol                  = "tcp"
  cidr_blocks               = [each.value.cidr_block]
  security_group_id         = aws_security_group.ec2.id
}

resource "aws_security_group_rule" "out-each-port-ec2-to-cidr" {
  for_each                  = var.sg_rules_egress_cidr_map
  type                      = "egress"
  from_port                 = each.value.port
  to_port                   = each.value.port
  protocol                  = "tcp"
  cidr_blocks               = [each.value.cidr_block]
  security_group_id         = aws_security_group.ec2.id
}

resource "aws_security_group_rule" "in-each-port-ec2-from-source_sg_id" {
  for_each                  = var.sg_rules_ingress_source_sg_map
  type                      = "ingress"
  from_port                 = each.value.port
  to_port                   = each.value.port
  protocol                  = "tcp"
  source_security_group_id  = each.value.source_sg_id
  security_group_id         = aws_security_group.ec2.id
}

resource "aws_security_group_rule" "out-each-port-ec2-to-source_sg_id" {
  for_each                  = var.sg_rules_egress_source_sg_map
  type                      = "egress"
  from_port                 = each.value.port
  to_port                   = each.value.port
  protocol                  = "tcp"
  source_security_group_id  = each.value.source_sg_id
  security_group_id         = aws_security_group.ec2.id
}

resource "aws_security_group_rule" "out-any-ec2-to-vpc" {
  count                     = var.enable_any_egress_to_vpc ? 1 : 0
  type                      = "egress"
  from_port                 = 0
  to_port                   = 65535
  protocol                  = "tcp"
  cidr_blocks               = [var.vpc_cidr]
  security_group_id         = aws_security_group.ec2.id
}

# This security group will be attached to RDS and not to EC2!
resource "aws_security_group" "ec2-to-database" {
  count                     = var.sg_rule_rds_port != null ? 1 : 0
  name                      = format("%s-to-db", var.name)
  description               = format("Rules for %s to database", var.name)
  vpc_id                    = var.vpc_id

  ingress {
    from_port       = var.sg_rule_rds_port
    to_port         = var.sg_rule_rds_port
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  tags = merge(
    {
      Name = format("%s-to-db", var.name)
    },
    var.tags,
  )
}

###########
# Key Pairs
###########
resource "aws_key_pair" "ec2" {
  key_name   = var.name
  public_key = var.ssh_pubkey
}

###############
# EC2 instances
###############
resource "aws_instance" "ec2" {
  count            = var.instance_count

  ami              = lookup(var.ami, var.region)
  instance_type    = var.instance_type
  user_data        = var.user_data
  user_data_base64 = var.user_data_base64
  subnet_id = length(var.network_interface) > 0 ? null : element(
    distinct(compact(tolist(var.subnet_ids))),
    count.index,
  )
  key_name               = aws_key_pair.ec2.id
  monitoring             = var.monitoring
  get_password_data      = var.get_password_data
  vpc_security_group_ids = [aws_security_group.ec2.id]
  iam_instance_profile   = var.iam_instance_profile

  associate_public_ip_address = var.associate_public_ip_address
  private_ip                  = length(var.private_ips) > 0 ? element(var.private_ips, count.index) : var.private_ip
  ipv6_address_count          = var.ipv6_address_count
  ipv6_addresses              = var.ipv6_addresses

  ebs_optimized = var.ebs_optimized

  dynamic "root_block_device" {
    for_each = var.root_block_device
    content {
      delete_on_termination = lookup(root_block_device.value, "delete_on_termination", null)
      encrypted             = lookup(root_block_device.value, "encrypted", null)
      iops                  = lookup(root_block_device.value, "iops", null)
      kms_key_id            = lookup(root_block_device.value, "kms_key_id", null)
      volume_size           = lookup(root_block_device.value, "volume_size", null)
      volume_type           = lookup(root_block_device.value, "volume_type", null)
    }
  }

  dynamic "ebs_block_device" {
    for_each = var.ebs_block_device
    content {
      delete_on_termination = lookup(ebs_block_device.value, "delete_on_termination", null)
      device_name           = ebs_block_device.value.device_name
      encrypted             = lookup(ebs_block_device.value, "encrypted", null)
      iops                  = lookup(ebs_block_device.value, "iops", null)
      kms_key_id            = lookup(ebs_block_device.value, "kms_key_id", null)
      snapshot_id           = lookup(ebs_block_device.value, "snapshot_id", null)
      volume_size           = lookup(ebs_block_device.value, "volume_size", null)
      volume_type           = lookup(ebs_block_device.value, "volume_type", null)
    }
  }

  dynamic "ephemeral_block_device" {
    for_each = var.ephemeral_block_device
    content {
      device_name  = ephemeral_block_device.value.device_name
      no_device    = lookup(ephemeral_block_device.value, "no_device", null)
      virtual_name = lookup(ephemeral_block_device.value, "virtual_name", null)
    }
  }

  dynamic "metadata_options" {
    for_each = length(keys(var.metadata_options)) == 0 ? [] : [var.metadata_options]
    content {
      http_endpoint               = lookup(metadata_options.value, "http_endpoint", "enabled")
      http_tokens                 = lookup(metadata_options.value, "http_tokens", "optional")
      http_put_response_hop_limit = lookup(metadata_options.value, "http_put_response_hop_limit", "1")
    }
  }

  dynamic "network_interface" {
    for_each = var.network_interface
    content {
      device_index          = network_interface.value.device_index
      network_interface_id  = lookup(network_interface.value, "network_interface_id", null)
      delete_on_termination = lookup(network_interface.value, "delete_on_termination", false)
    }
  }

  source_dest_check                    = length(var.network_interface) > 0 ? null : var.source_dest_check
  disable_api_termination              = var.disable_api_termination
  instance_initiated_shutdown_behavior = var.instance_initiated_shutdown_behavior
  placement_group                      = var.placement_group
  tenancy                              = var.tenancy

  tags = merge(
    {
      "Name" = format("%s-%s", var.name, count.index + 1)
    },
    var.tags,
    var.backup_tags,
  )

  volume_tags = merge(
    {
      "Name" = format("%s-%s", var.name, count.index + 1)
    },
    var.volume_tags,
  )

  credit_specification {
    cpu_credits = local.is_t_instance_type ? var.cpu_credits : null
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

##################
# EIP associations
##################
resource "aws_eip_association" "ec2" {
  count         = var.eip_alloc_ids != null ? length(var.eip_alloc_ids) :0
  instance_id   = aws_instance.ec2[count.index].id
  allocation_id = var.eip_alloc_ids[count.index]
}

##################
# CloudWatch Alarm
##################
resource "aws_cloudwatch_metric_alarm" "ec2-autorecover" {
  count                     = var.cloudwatch_autorecover_enabled && var.cloudwatch_sns_topic_arn == null ? var.instance_count : 0
  alarm_name                = format("%s-%s-autorecover", var.name, count.index + 1)
  namespace                 = "AWS/EC2"
  evaluation_periods        = "2"
  period                    = "60"
  alarm_description         = format("Recover server %s-%s when underlying hardware fails.", var.name, count.index + 1)
  alarm_actions             = ["arn:aws:automate:${var.region}:ec2:recover"]
  statistic                 = "Minimum"
  comparison_operator       = "GreaterThanThreshold"
  threshold                 = "0"
  metric_name               = "StatusCheckFailed_System"
  dimensions = {
    InstanceId = element(aws_instance.ec2.*.id, count.index)
  }
}

resource "aws_cloudwatch_metric_alarm" "ec2-autorecover-and-notify" {
  count                     = var.cloudwatch_autorecover_enabled && var.cloudwatch_sns_topic_arn != null ? var.instance_count : 0
  alarm_name                = format("%s-%s-autorecover-and-notify", var.name, count.index + 1)
  namespace                 = "AWS/EC2"
  evaluation_periods        = "2"
  period                    = "60"
  alarm_description         = format("Recover server %s-%s when underlying hardware fails.", var.name, count.index + 1)
  alarm_actions             = ["arn:aws:automate:${var.region}:ec2:recover", var.cloudwatch_sns_topic_arn]
  statistic                 = "Minimum"
  comparison_operator       = "GreaterThanThreshold"
  threshold                 = "0"
  metric_name               = "StatusCheckFailed_System"
  dimensions = {
    InstanceId = element(aws_instance.ec2.*.id, count.index)
  }
}

resource "aws_cloudwatch_metric_alarm" "ec2-cpu-utilization-notify" {
  count                     = var.cloudwatch_cpu_utilization_enabled && var.cloudwatch_sns_topic_arn != null ? var.instance_count : 0
  alarm_name                = format("%s-%s-cpu-utilization", var.name, count.index + 1)
  namespace                 = "AWS/EC2"
  evaluation_periods        = "2"
  period                    = "120"
  alarm_description         = "This metric monitors ec2 cpu utilization"
  alarm_actions             = [var.cloudwatch_sns_topic_arn]
  ok_actions                = [var.cloudwatch_sns_topic_arn]
  statistic                 = "Average"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  threshold                 = "80"
  metric_name               = "CPUUtilization"
  dimensions = {
    InstanceId = element(aws_instance.ec2.*.id, count.index)
  }
}

#######################
# Backup vault and plan
#######################
resource "aws_backup_vault" "ec2" {
  count         = var.backup_enabled ? var.instance_count : 0
  name          = format("%s-%s-backup-vault", var.name, count.index + 1)
  kms_key_arn   = var.backup_vault_kms_key_arn
}

resource "aws_backup_plan" "ec2" {
  count         = var.backup_enabled ? var.instance_count : 0
  name          = format("%s-%s-backup-plan", var.name, count.index + 1)

  rule {
    rule_name         = format("%s-%s-backup-rule", var.name, count.index + 1)
    target_vault_name = aws_backup_vault.ec2[count.index].name
    schedule          = var.backup_plan_schedule

    dynamic "lifecycle" {
      for_each    = var.backup_plan_cold_storage_after != null || var.backup_plan_delete_after != null ? ["true"] : []
      content {
        cold_storage_after    = var.backup_plan_cold_storage_after
        delete_after          = var.backup_plan_delete_after
      }
    }
  }

  advanced_backup_setting {
    backup_options = {
      WindowsVSS = var.backup_plan_windows_vss
    }
    resource_type = "EC2"
  }
}

resource "aws_iam_role" "ec2_backup" {
  count                 = var.backup_enabled && var.backup_create_role ? 1 : 0
  name                  = var.backup_role_name

  assume_role_policy    = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "backup.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ec2_backup_backup" {
  count         = var.backup_enabled && var.backup_create_role ? 1 : 0
  role          = aws_iam_role.ec2_backup[count.index].name
  policy_arn    = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "ec2_backup_restores" {
  count         = var.backup_enabled && var.backup_create_role ? 1 : 0
  role          = aws_iam_role.ec2_backup[count.index].name
  policy_arn    = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_backup_selection" "ec2" {
  count         = var.backup_enabled ? var.instance_count : 0
  iam_role_arn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.backup_role_name}"
  name          = format("%s-%s-backup-selection", var.name, count.index + 1)
  plan_id       = aws_backup_plan.ec2[count.index].id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = var.backup_plan_tag_key
    value = var.backup_plan_tag_value
  }
}