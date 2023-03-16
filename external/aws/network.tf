#Virtual Private Cloud
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_network_acl
resource "aws_vpc" "infra_vpc" {
  cidr_block = var.vpc_cidr_block
  tags = {
    Op = var.engagement_name
    Name = var.engagement_name
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.infra_vpc.id
  tags = {
    Name = "vpc_shared_internet_gw"
  }
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.infra_vpc.id
  tags = {
    Op = var.engagement_name
    Name = format("%s_route_table", var.engagement_name)
  }
}




# Subnets
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_subnet

resource "aws_subnet" "infra" {
  availability_zone = var.availability_zone
  vpc_id = aws_vpc.infra_vpc.id
  cidr_block = var.vpc_cidr_block
  tags = {
    Op = var.engagement_name
    name = format("%s_subnet", var.engagement_name)
  }
}
#Routes
resource "aws_route" "op_internet_access" {
  route_table_id        = aws_route_table.rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}

resource "aws_route_table_association" "rt_assoc" {
  subnet_id      = aws_subnet.infra.id
  route_table_id = aws_route_table.rt.id
}




# Security Groups

resource "aws_security_group" "ssh_from_company" {
  
  name = format("%s_ssh_from_company", var.engagement_name)
  description = "Allow incoming ssh connections"
  vpc_id = aws_vpc.infra_vpc.id
  dynamic "ingress" {
    for_each = var.ssh_allowed_cidr_ranges
    
    content {
      
    
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = [ingress.value]
    }
    

  }
  tags = {
    Op = var.engagement_name
    Name = format("%s_ssh_from_company", var.engagement_name)
  }
    
  
  
}

resource "aws_security_group" "ssh_from_anywhere" {
    name = format("%s_ssh_from_anywhere", var.engagement_name)
  description = "Allow incoming ssh connections"
  vpc_id = aws_vpc.infra_vpc.id
  ingress  {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags ={
    Op = var.engagement_name
    Name = format("%s_ssh_from_anywhere", var.engagement_name)
  }
  
}
resource "aws_security_group" "internal" {
  name = "${var.engagement_name}_internal"
  description = "Allow subnet connectivity"
  vpc_id = aws_vpc.infra_vpc.id
  ingress  {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["192.168.0.0/16"]
  }
  egress  {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Op = "${var.engagement_name}"
    Name = "${var.engagement_name}_internal"
  }
}

resource "aws_security_group" "web_from_all" {
  name = format("%s_web_from_all", var.engagement_name)
  description = "Allow incoming http(s) connections"
  vpc_id = aws_vpc.infra_vpc.id
  ingress  {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress  {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Op = var.engagement_name
    Name = format("%s_web_from_all", var.engagement_name)
  }
}

resource "aws_security_group" "dns_from_all" {
  name = format("%s_dns_from_all", var.engagement_name)
  description = "Allow incoming dns connections"
  vpc_id = "${aws_vpc.infra_vpc.id}"
  ingress  {
    from_port = 53
    to_port = 53
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress  {
    from_port = 53
    to_port = 53
    protocol = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Op = "${var.engagement_name}"
    Name = "${var.engagement_name}_dns_from_all"
  }
}