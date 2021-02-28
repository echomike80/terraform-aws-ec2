# AWS EC2 Terraform module

Terraform module which creates EC2 resources with security groups, key pair, EIP associations and CloudWatch alarms on AWS.

## Terraform versions

Terraform 0.12 and newer. 

## Usage

```hcl
module "applicationserver" {
  source                            = "/path/to/module/terraform-aws-ec2"
  name                              = var.name
  type                              = "app"
  region                            = var.region
  vpc_cidr                          = var.vpc_cidr
  vpc_id                            = var.vpc_id
  subnet_ids                        = var.subnet_ids

  sg_rules_egress_cidr_map          = {
    internet_http = {
      port          = 80
      cidr_block    = "0.0.0.0/0"
    }
    internet_https = {
      port          = 443
      cidr_block    = "0.0.0.0/0"
    }
  }
  sg_rules_ingress_cidr_map         = {
    vpn_ssh = {
      port          = 22
      cidr_block    = "192.168.178.0/24"
    }
  }
  sg_rules_ingress_source_sg_map    = {
    webserver_http = {
      port          = 8080
      source_sg_id  = "sg-........."
    }
  }

  ami                               = var.app_ami
  instance_count                    = var.app_instance_count
  instance_type                     = var.app_instance_type
  iam_instance_profile              = var.app_iam_instance_profile
  ssh_pubkey                        = var.app_ssh_pubkey
  root_block_device                 = var.app_root_block_device
  ebs_block_device                  = var.app_ebs_block_device
  sg_rule_rds_port                  = var.app_sg_rule_rds_port

  tags = {
    Environment = var.environment,
    Project     = var.project,
    Tier        = var.app_tier
  }
}
```

Mandatory input variables:
```
ami = {
  "eu-central-1" = "ami-0a6dc7529cd559185"
  "eu-west-1"    = "ami-0fc970315c2d38f01"
  "us-east-1"    = "ami-047a51fa27710816e"
}
instance_type = "t2.medium"
region = "eu-central-1"
ssh_pubkey = "ssh-rsa AAAAB3NzaC1.... ec2"
type = "app"
vpc_id = "vpc-......"
```

## Notes

1. Current issue: `cloudwatch_sns_topic_arn` can only be used after EC2 instance was provisioned by this module. So you need to run first without `cloudwatch_sns_topic_arn`.

## Requirements

| Name | Version |       
|------|---------|       
| terraform | >= 0.12.6 |
| aws | >= 2.65 |        

## Providers

| Name | Version |       
|------|---------|       
| aws | >= 2.65 |        

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| ami | ID of AMI to use for the instance | `map` | n/a | yes |
| associate\_public\_ip\_address | If true, the EC2 instance will have associated public IP address | `bool` | `null` | no |
| cloudwatch\_autorecover\_enabled | Enable or disable CloudWatch alarm EC2 autorecover | `bool` | `true` | no |
| cloudwatch\_cpu\_utilization\_enabled | Enable or disable CloudWatch alarm CPU utilization | `bool` | `false` | no |
| cloudwatch\_sns\_topic\_arn | SNS Topic ARN for CloudWatch alarms | `string` | `null` | no |
| cpu\_credits | The credit option for CPU usage (unlimited or standard) | `string` | `"standard"` | no |
| disable\_api\_termination | If true, enables EC2 Instance Termination Protection | `bool` | `false` | no |
| ebs\_block\_device | Additional EBS block devices to attach to the instance | `list(map(string))` | `[]` | no |
| ebs\_optimized | If true, the launched EC2 instance will be EBS-optimized | `bool` | `false` | no |
| eip\_alloc\_ids | List of Elastic IP associations for the EC2 instance | `list(string)` | `null` | no |
| enable\_any\_egress\_to\_vpc | Enable any egress traffic from EC2 instance to VPC | `bool` | `true` | no |
| ephemeral\_block\_device | Customize Ephemeral (also known as Instance Store) volumes on the instance | `list(map(string))` | `[]` | no |
| get\_password\_data | If true, wait for password data to become available and retrieve it. | `bool` | `false` | no |
| iam\_instance\_profile | The IAM Instance Profile to launch the instance with. Specified as the name of the Instance Profile. | `string` | `""` | no |
| instance\_count | Number of instances to launch | `number` | `1` | no |
| instance\_initiated\_shutdown\_behavior | Shutdown behavior for the instance | `string` | `""` | no |
| instance\_type | The type of instance to start | `string` | n/a | yes |
| ipv6\_address\_count | A number of IPv6 addresses to associate with the primary network interface. Amazon EC2 chooses the IPv6 addresses from the range of your subnet. | `number` | `null` | no |
| ipv6\_addresses | Specify one or more IPv6 addresses from the range of the subnet to associate with the primary network interface | `list(string)` | `null` | no |
| metadata\_options | Customize the metadata options of the instance | `map(string)` | `{}` | no |
| monitoring | If true, the launched EC2 instance will have detailed monitoring enabled | `bool` | `false` | no |
| name | Name to be used on all resources as prefix | `string` | n/a | yes |
| network\_interface | Customize network interfaces to be attached at instance boot time | `list(map(string))` | `[]` | no |
| num\_suffix\_format | Numerical suffix format used as the volume and EC2 instance name suffix | `string` | `"-%d"` | no |
| placement\_group | The Placement Group to start the instance in | `string` | `""` | no |
| private\_ip | Private IP address to associate with the instance in a VPC | `string` | `null` | no |
| private\_ips | A list of private IP address to associate with the instance in a VPC. Should match the number of instances. | `list(string)` | `[]` | no |
| region | Name of region | `string` | n/a | yes |
| root\_block\_device | Customize details about the root block device of the instance. See Block Devices below for details | `list(map(string))` | `[]` | no |
| sg\_rule\_rds\_port | Port for ingress security group rules to RDS | `number` | `null` | no |
| sg\_rules\_egress\_cidr\_map | Map of security group rules for egress communication of cidr | `map` | `{}` | no |
| sg\_rules\_egress\_source\_sg\_map | Map of security group rules for egress communication of security group source ids | `map` | `{}` | no |
| sg\_rules\_ingress\_cidr\_map | Map of security group rules for ingress communication of cidr | `map` | `{}` | no |
| sg\_rules\_ingress\_source\_sg\_map | Map of security group rules for ingress communication of security group source ids | `map` | `{}` | no |
| source\_dest\_check | Controls if traffic is routed to the instance when the destination address does not match the instance. Used for NAT or VPNs. | `bool` | `true` | no |
| ssh\_pubkey | SSH Public Key | `string` | n/a | yes |
| subnet\_id | The VPC Subnet ID to launch in | `string` | `""` | no |
| subnet\_ids | A list of VPC Subnet IDs to launch in | `list(string)` | `[]` | no |
| tags | A mapping of tags to assign to the resource | `map(string)` | `{}` | no |
| tenancy | The tenancy of the instance (if the instance is running in a VPC). Available values: default, dedicated, host. | `string` | `"default"` | no |
| type | Type of the application server | `string` | n/a | yes |
| use\_num\_suffix | Always append numerical suffix to instance name, even if instance\_count is 1 | `bool` | `false` | no |
| user\_data | The user data to provide when launching the instance. Do not pass gzip-compressed data via this argument; see user\_data\_base64 instead. | `string` | `null` | no |
| user\_data\_base64 | Can be used instead of user\_data to pass base64-encoded binary data directly. | `string` | `null` | no |
| volume\_tags | A mapping of tags to assign to the devices created by the instance at launch time | `map(string)` | `{}` | no |
| vpc\_cidr | VPC cidr for security group rules | `string` | `"10.0.0.0/16"` | no |
| vpc\_id | String of vpc id | `string` | n/a | yes |
| vpc\_security\_group\_ids | A list of security group IDs to associate with | `list(string)` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| arn | List of ARNs of instances |
| availability\_zone | List of availability zones of instances |
| credit\_specification | List of credit specification of instances |
| ebs\_block\_device\_volume\_ids | List of volume IDs of EBS block devices of instances |
| id | List of IDs of instances |
| instance\_count | Number of instances to launch specified as argument to this module |
| instance\_state | List of instance states of instances |
| ipv6\_addresses | List of assigned IPv6 addresses of instances |
| key\_name | List of key names of instances |
| metadata\_options | List of metadata options of instances |
| password\_data | List of Base-64 encoded encrypted password data for the instance |
| placement\_group | List of placement groups of instances |
| primary\_network\_interface\_id | List of IDs of the primary network interface of instances |
| private\_dns | List of private DNS names assigned to the instances. Can only be used inside the Amazon EC2, and only available if you've enabled DNS hostnames for your VPC |
| private\_ip | List of private IP addresses assigned to the instances |
| public\_dns | List of public DNS names assigned to the instances. For EC2-VPC, this is only available if you've enabled DNS hostnames for your VPC |
| public\_ip | List of public IP addresses assigned to the instances, if applicable |
| root\_block\_device\_volume\_ids | List of volume IDs of root block devices of instances |
| security\_group\_id\_database\_from\_ec2 | ID of security group to use for the RDS that allows incoming connections from the application server |
| security\_group\_id\_ec2 | ID of security group to use for the application server |
| security\_groups | List of associated security groups of instances |
| subnet\_id | List of IDs of VPC subnets of instances |
| tags | List of tags of instances |
| volume\_tags | List of tags of volumes of instances |
| vpc\_security\_group\_ids | List of associated security groups of instances, if running in non-default VPC |

## Authors

Module managed by [Marcel Emmert](https://github.com/echomike80).
Module based on AWS EC2 instance module created by [Anton Babenko](https://github.com/terraform-aws-modules/terraform-aws-ec2-instance).

## License

Apache 2 Licensed. See LICENSE for full details.
