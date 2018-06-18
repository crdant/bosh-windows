resource "aws_directory_service_directory" "bosh" {
  name     = "bosh.aws.crdant.io"
  password = "w3lkin-piGSKin-ent!tle"
  edition  = "Standard"
  type     = "MicrosoftAD"

  vpc_settings {
    vpc_id     = "${aws_vpc.vpc.id}"
    subnet_ids = [ "${aws_subnet.internal_subnets.0.id}", "${aws_subnet.internal_subnets.1.id}"]
  }

  tags {
    Project = "foo"
  }
}


resource "aws_security_group" "directory_access" {
  name        = "${var.env_id}-directory-access"
  description = "Active Directory Internal"
  vpc_id      = "${local.vpc_id}"

  tags {
    Name = "${var.env_id}--directory-access-security-group"
  }

  lifecycle {
    ignore_changes = ["name"]
  }
}

resource "aws_security_group_rule" "directory_access_dns_udp_ingress" {
  type        = "ingress"
  protocol    = "udp"
  from_port   = "53"
  to_port     = "53"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_dns_tcp_ingress" {
  type        = "egress"
  protocol    = "tcp"
  from_port   = "53"
  to_port     = "53"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_dns_udp_egress" {
  type        = "egress"
  protocol    = "udp"
  from_port   = "53"
  to_port     = "53"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_dns_tcp_egress" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "53"
  to_port     = "53"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}


resource "aws_security_group_rule" "directory_access_kerberos_tcp" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "88"
  to_port     = "88"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_ldap_kerberos_udp" {
  type        = "ingress"
  protocol    = "udp"
  from_port   = "88"
  to_port     = "88"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_time" {
  type        = "ingress"
  protocol    = "udp"
  from_port   = "123"
  to_port     = "123"
  cidr_blocks = [ "${aws_subnet.internal_subnets.*.cidr_block}" ]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_rpc_mapper" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "135"
  to_port     = "135"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_ldap_tcp" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "389"
  to_port     = "389"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_ldap_udp" {
  type        = "ingress"
  protocol    = "udp"
  from_port   = "389"
  to_port     = "389"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_smb" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "445"
  to_port     = "445"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_kerberos_pwd" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "464"
  to_port     = "464"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_ldap_tls" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "636"
  to_port     = "636"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_ldap_gc" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "3268"
  to_port     = "3269"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_ldap_rpc_ingress" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = "49152"
  to_port     = "65535"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

resource "aws_security_group_rule" "directory_access_ldap_rpc_egress" {
  type        = "egress"
  protocol    = "tcp"
  from_port   = "49152"
  to_port     = "65535"
  cidr_blocks = ["${aws_subnet.internal_subnets.*.cidr_block}"]

  security_group_id = "${aws_security_group.directory_access.id}"
}

output "directory_security_group" {
  value = "${aws_security_group.directory_access.id}"
}

output "directory_dns_addresses" {
  value = "${aws_directory_service_directory.bosh.dns_ip_addresses}"
}
