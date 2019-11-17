// SPDX-FileCopyrightText: ©  Basil Peace
// SPDX-License-Identifier: Apache-2.0
terraform {
  required_version = "~> 0.12"
  backend "artifactory" {
    url      = "https://fidata.jfrog.io/fidata"
    repo     = "terraform-state"
    subpath  = "fidata.org"
  }
}

# Providers

provider "aws" {
  version = "~> 2.36"
  region = "eu-west-1"
}

provider "cloudflare" {
  version = "~> 2.1"
}

provider "external" {
  version = "~> 1.2"
}

# IAMs

resource "aws_iam_user" "fidata_jenkins" {
  name = "fidata-jenkins"
}
resource "aws_iam_access_key" "fidata_jenkins" {
  user = aws_iam_user.fidata_jenkins.name
}
resource "aws_iam_user_policy" "fidata_jenkins" {
  name = "fidata-jenkins"
  user = aws_iam_user.fidata_jenkins.name
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1312295543082",
      "Action": [
        "ec2:DescribeSpotInstanceRequests",
        "ec2:CancelSpotInstanceRequests",
        "ec2:GetConsoleOutput",
        "ec2:RequestSpotInstances",
        "ec2:RunInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:DescribeInstances",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeRegions",
        "ec2:DescribeImages",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:CreateKeyPair",
        "ec2:ImportKeyPair"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
output "fidata_jenkins_iam_access_key" {
  value = aws_iam_access_key.fidata_jenkins.id
}
output "fidata_jenkins_iam_secret_key" {
  value = aws_iam_access_key.fidata_jenkins.secret
}

# VPC

resource "aws_vpc" "fidata" {
  cidr_block = "172.31.0.0/16"
  instance_tenancy = "default"
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = {
    Name = "FIDATA"
  }
}
output "fidata_vpc_id" {
  value = aws_vpc.fidata.id
}

resource "aws_subnet" "fidata" {
  vpc_id = aws_vpc.fidata.id
  availability_zone = "eu-west-1c"
  cidr_block = "172.31.0.0/20"
  map_public_ip_on_launch = true
  tags = {
    Name = "FIDATA"
  }
}
output "fidata_subnet_id" {
  value = aws_subnet.fidata.id
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.fidata.id
}

resource "aws_vpc_dhcp_options" "dns_resolver" {
  domain_name = "eu-west-1.compute.internal"
  domain_name_servers = ["172.31.0.2"]
}

resource "aws_vpc_dhcp_options_association" "dns_resolver" {
  vpc_id = aws_vpc.fidata.id
  dhcp_options_id = aws_vpc_dhcp_options.dns_resolver.id
}

resource "aws_default_network_acl" "fidata" {
  default_network_acl_id = aws_vpc.fidata.default_network_acl_id
  subnet_ids = [aws_subnet.fidata.id]
  egress {
    rule_no = 100
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_block = "0.0.0.0/0"
    action = "allow"
  }
  ingress {
    rule_no = 100
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_block = "0.0.0.0/0"
    action = "allow"
  }
  tags = {
    Name = "main"
  }
}
  
resource "aws_route_table" "r" {
  vpc_id = aws_vpc.fidata.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_main_route_table_association" "a" {
  vpc_id = aws_vpc.fidata.id
  route_table_id = aws_route_table.r.id
}

resource "aws_route_table_association" "a" {
  subnet_id = aws_subnet.fidata.id
  route_table_id = aws_route_table.r.id
}

# Security Groups

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "icmp"
    from_port = 3 # Destination Unreachable
    to_port = 4 #  Fragmentation Needed and Don't Fragment was Set
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
output "default_security_group_id" {
  value = aws_default_security_group.default.id
}

resource "aws_security_group" "ICMP_private" {
  name = "ICMP_private"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "icmp"
    from_port = 11 # Time Exceeded
    to_port = 0 # Time to Live exceeded in Transit
    cidr_blocks = [aws_vpc.fidata.cidr_block]
  }
  ingress {
    protocol = "icmp"
    from_port = 8 # Echo
    to_port = 0 # No Code
    cidr_blocks = [aws_vpc.fidata.cidr_block]
  }
}
output "ICMP_private_security_group_id" {
  value = aws_security_group.ICMP_private.id
}

resource "aws_security_group" "ICMP" {
  name = "ICMP"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "icmp"
    from_port = 11 # Time Exceeded
    to_port = 0 # Time to Live exceeded in Transit
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol = "icmp"
    from_port = 8 # Echo
    to_port = 0 # No Code
    cidr_blocks = ["0.0.0.0/0"]
  }
}
output "ICMP_security_group_id" {
  value = aws_security_group.ICMP.id
}

resource "aws_security_group" "NFS_private" {
  name = "NFS_private"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 2049
    to_port = 2049
    cidr_blocks = [aws_vpc.fidata.cidr_block]
  }
}
output "NFS_private_security_group_id" {
  value = aws_security_group.NFS_private.id
}

resource "aws_security_group" "PostgreSQL_private" {
  name = "PostgreSQL_private"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 5432
    to_port = 5432
    cidr_blocks = [aws_vpc.fidata.cidr_block]
  }
}
output "PostgreSQL_private_security_group_id" {
  value = aws_security_group.PostgreSQL_private.id
}

resource "aws_security_group" "SSH_private" {
  name = "SSH_private"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = [aws_vpc.fidata.cidr_block]
  }
}
output "SSH_private_security_group_id" {
  value = aws_security_group.SSH_private.id
}

resource "aws_security_group" "SSH" {
  name = "SSH"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
output "SSH_security_group_id" {
  value = aws_security_group.SSH.id
}

resource "aws_security_group" "WinRM_private" {
  name = "WinRM_private"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 5986
    to_port = 5986
    cidr_blocks = [aws_vpc.fidata.cidr_block]
  }
}
output "WinRM_private_security_group_id" {
  value = aws_security_group.WinRM_private.id
}

resource "aws_security_group" "WinRM" {
  name = "WinRM"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 5986
    to_port = 5986
    cidr_blocks = ["0.0.0.0/0"]
  }
}
output "WinRM_security_group_id" {
  value = aws_security_group.WinRM.id
}

resource "aws_security_group" "JNLP_private" {
  name = "JNLP_private"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 49817
    to_port = 49817
    cidr_blocks = [aws_vpc.fidata.cidr_block]
  }
}
output "JNLP_private_security_group_id" {
  value = aws_security_group.JNLP_private.id
}

resource "aws_security_group" "RDP" {
  name = "RDP"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 3389
    to_port = 3389
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol = "udp"
    from_port = 3389
    to_port = 3389
    cidr_blocks = ["0.0.0.0/0"]
  }
}
output "RDP_security_group_id" {
  value = aws_security_group.RDP.id
}

resource "aws_security_group" "HTTP_S" {
  name = "HTTP(S)"
  vpc_id = aws_vpc.fidata.id
  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol = "tcp"
    from_port = 443
    to_port = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol = "icmp"
    from_port = 8
    to_port = 8
    cidr_blocks = ["0.0.0.0/0"]
  }
}
output "HTTP_S_security_group_id" {
  value = aws_security_group.HTTP_S.id
}

# Key Pairs

data "external" "fidata_main_ssh_key" {
  program = [
    "npx",
    "jjo",
    "contents=@../build/keys/fidata-main.pub"
  ]
}
resource "aws_key_pair" "fidata_main" {
  key_name = "fidata-main"
  public_key = data.external.fidata_main_ssh_key.result.contents
}

data "external" "fidata_jenkins_ssh_key" {
  program = [
    "npx",
    "jjo",
    "contents=@../build/keys/fidata-jenkins.pub"
  ]
}
resource "aws_key_pair" "fidata_jenkins" {
  key_name = "fidata-jenkins"
  public_key = data.external.fidata_jenkins_ssh_key.result.contents
}

data "external" "kitchen_ssh_key" {
  program = [
    "npx",
    "jjo",
    "contents=@../build/keys/kitchen.pub"
  ]
}
resource "aws_key_pair" "kitchen" {
  key_name = "kitchen"
  public_key = data.external.kitchen_ssh_key.result.contents
}

# DNS

resource "cloudflare_zone" "fidata_org" {
  zone = "fidata.org"
}
output "fidata_org_zone_id" {
  value = cloudflare_zone.fidata_org.id
}

resource "cloudflare_record" "artifactory" {
  zone_id = cloudflare_zone.fidata_org.id
  name = "artifactory"
  type = "CNAME"
  value = "fidata.jfrog.io"
  proxied = true
}

resource "cloudflare_record" "CAA_letsencrypt" {
  zone_id = cloudflare_zone.fidata_org.id
  name = cloudflare_zone.fidata_org.zone
  type = "CAA"
  data = {
    flags = 0
    tag = "issue"
    value = "letsencrypt.org"
  }
}

resource "cloudflare_record" "CAA_mailto_1" {
  zone_id = cloudflare_zone.fidata_org.id
  name = cloudflare_zone.fidata_org.zone
  type = "CAA"
  data = {
    flags = 0
    tag = "iodef"
    value = "mailto:grv87@yandex.ru"
  }
}

resource "cloudflare_record" "CAA_mailto_2" {
  zone_id = cloudflare_zone.fidata_org.id
  name = cloudflare_zone.fidata_org.zone
  type = "CAA"
  data = {
    flags = 0
    tag = "iodef"
    value = "mailto:basil.peace@gmail.com"
  }
}

resource "cloudflare_record" "google_verification" {
  zone_id = cloudflare_zone.fidata_org.id
  name = cloudflare_zone.fidata_org.zone
  type = "TXT"
  data = {
    "google-site-verification" = "psnXZZeicyuiPxDaBDb37QCl2k90-wV4lJrg6NOpIs0"
  }
  ttl = 3600
}

resource "cloudflare_record" "github_verify_domain" {
  zone_id = cloudflare_zone.fidata_org.id
  name = "_github-challenge-fidata"
  type = "TXT"
  value = "34336fee0d"
}

resource "cloudflare_record" "yandex_mail_verification" {
  zone_id = cloudflare_zone.fidata_org.id
  name = "yamail-bde06f1e7c17"
  type = "CNAME"
  value = "mail.yandex.ru"
  proxied = false
}

resource "cloudflare_record" "mail" {
  zone_id = cloudflare_zone.fidata_org.id
  name = cloudflare_zone.fidata_org.zone
  type = "MX"
  value = "mx.yandex.net"
  priority = 10
}

resource "cloudflare_record" "mail_subdomain" {
  zone_id = cloudflare_zone.fidata_org.id
  name = "mail"
  type = "CNAME"
  value = "domain.mail.yandex.net"
}

resource "cloudflare_record" "yandex_mail_dkim" {
  zone_id = cloudflare_zone.fidata_org.id
  name = "mail._domainkey"
  type = "TXT"
  data = {
    v = "DKIM1;"
    k = "rsa;"
    t = "s;" # Turn DKIM on
    p = <<EOF
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtZQIP0/9gZXNCT/UCY1HA2cBn/42wZfEVc2Z0gebYAnj6KiUf80OitmNkn72WEyDJmppEa/X6sNpRonSOJGer4nz92sjvaMIaI2JXCiw5/aefAVA1V54UMmvpQMtcfe70pcRpZW4ZHwVJnb+HhNzjZZtCThIsQyu/3/bKEUeYJwIDAQAB;
EOF
  }
}

resource "cloudflare_record" "spf_txt" {
  zone_id = cloudflare_zone.fidata_org.id
  name = cloudflare_zone.fidata_org.zone
  type = "TXT"
  data = {
    v = "spf1"
    redirect = "_spf.yandex.net"
  }
}

resource "cloudflare_record" "spf" {
  zone_id = cloudflare_zone.fidata_org.id
  name = cloudflare_zone.fidata_org.zone
  type = "SPF"
  data = {
    v = "spf1"
    redirect = "_spf.yandex.net"
  }
}

resource "cloudflare_page_rule" "always_use_HTTPS" {
  zone_id = cloudflare_zone.fidata_org.id
  target = "http://*${cloudflare_zone.fidata_org.zone}/*"
  priority = 3
  actions {
    always_use_https = true
  }
}

resource "cloudflare_page_rule" "artifactory" {
  zone_id = cloudflare_zone.fidata_org.id
  target = "artifactory.${cloudflare_zone.fidata_org.zone}/"
  priority = 1
  actions {
    forwarding_url {
      status_code = 301 # Permanent Redirect
      url = "https://fidata.jfrog.io/"
    }
  }
}
