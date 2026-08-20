data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_vpc" "experiment" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.experiment_group}-vpc"
  }
}

resource "aws_internet_gateway" "experiment" {
  vpc_id = aws_vpc.experiment.id

  tags = {
    Name = "${var.experiment_group}-igw"
  }
}

resource "aws_subnet" "nodes" {
  vpc_id                  = aws_vpc.experiment.id
  cidr_block              = var.node_subnet_cidr
  availability_zone_id    = var.availability_zone_id
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_route_table" "nodes" {
  vpc_id = aws_vpc.experiment.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.experiment.id
  }

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_route_table_association" "nodes" {
  subnet_id      = aws_subnet.nodes.id
  route_table_id = aws_route_table.nodes.id
}

resource "aws_security_group" "nodes" {
  name_prefix = "${var.experiment_group}-nodes-"
  description = "Private protocol traffic and outbound SSM only"
  vpc_id      = aws_vpc.experiment.id

  egress {
    description = "Outbound package, SSM, and artifact access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.experiment_group}-nodes"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "private_self" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  description                  = "All private traffic between experiment nodes"
  ip_protocol                  = "-1"
}

resource "aws_security_group_rule" "public_protocol_local" {
  count = var.enable_public_protocol && !var.protocol_public_world_ingress ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.nodes.id
  description       = "Protocol TCP from local experiment public IPv4 addresses"
  protocol          = "tcp"
  from_port         = var.protocol_public_port_from
  to_port           = var.protocol_public_port_to
  cidr_blocks       = [for node in aws_instance.node : "${node.public_ip}/32"]
}

resource "aws_vpc_security_group_ingress_rule" "public_protocol_peer" {
  for_each = var.enable_public_protocol && !var.protocol_public_world_ingress ? toset(var.protocol_public_peer_cidrs) : toset([])

  security_group_id = aws_security_group.nodes.id
  description       = "Protocol TCP from allowlisted peer IPv4"
  ip_protocol       = "tcp"
  from_port         = var.protocol_public_port_from
  to_port           = var.protocol_public_port_to
  cidr_ipv4         = each.value
}

resource "aws_security_group_rule" "public_protocol_large_fleet" {
  count = var.enable_public_protocol && var.protocol_public_world_ingress ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.nodes.id
  description       = "Temporary authenticated protocol ingress for a large public experiment fleet"
  protocol          = "tcp"
  from_port         = var.protocol_public_port_from
  to_port           = var.protocol_public_port_to
  cidr_blocks       = [var.protocol_public_ingress_cidr]
}

resource "aws_iam_role" "nodes" {
  name_prefix        = "${var.experiment_group}-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "nodes" {
  name_prefix = "${var.experiment_group}-"
  role        = aws_iam_role.nodes.name

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_instance" "node" {
  count = var.instance_count

  ami                         = var.ami_id != "" ? var.ami_id : data.aws_ssm_parameter.al2023_arm64.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.nodes.id
  private_ip                  = cidrhost(aws_subnet.nodes.cidr_block, count.index + var.node_private_ip_offset)
  vpc_security_group_ids      = [aws_security_group.nodes.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.nodes.name

  instance_market_options {
    market_type = "spot"

    spot_options {
      instance_interruption_behavior = "terminate"
      spot_instance_type             = "one-time"
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted             = true
    delete_on_termination = true
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
  }

  user_data = "${file("${path.module}/user-data.sh")}\nprintf '%s\\n' '${count.index + var.node_slot_offset}' > /etc/rladkr/node-slot\n"

  tags = {
    Name     = format("%s-node-%03d", var.experiment_group, count.index + var.node_slot_offset)
    NodeSlot = tostring(count.index + var.node_slot_offset)
  }

  depends_on = [aws_iam_role_policy_attachment.ssm]
}
