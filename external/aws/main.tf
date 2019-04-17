# FIXME: Put a meaningful comment here

# this is basically a workaround for
# https://github.com/hashicorp/terraform/issues/14343
locals {
  instance_type = "${lookup(var.instance_types, var.env)}"
  private_key_contents = "${file(var.key_name)}"
  public_key_contents = "${file(format("%s.pub", var.key_name))}"
}

provider "aws" {
  region = "${var.region}"
  version = "~> 2.4.0"
  shared_credentials_file = "${var.shared_credentials_file}"
  profile = "${var.profile}"
}

resource "aws_key_pair" "op" {
  key_name = "${var.aws_key_name}"
  public_key = "${local.public_key_contents}"
}

resource "aws_vpc" "op" {
  cidr_block = "${var.subnet_cidr}"
  tags = {
    Op = "${var.op_name}"
    Name = "${var.op_name}"
  }
}

resource "aws_subnet" "internal-subnet" {
  availability_zone = "${var.availability_zone}"
  vpc_id = "${aws_vpc.op.id}"
  cidr_block = "192.168.0.0/16"
  tags {
    Op = "${var.op_name}"
    name = "${var.op_name}_subnet"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.op.id}"

  tags {
    Name = "${var.op_name}_IGW"
  }
}
resource "aws_route_table" "rt" {
  vpc_id = "${aws_vpc.op.id}"
  tags {
    Op = "${var.op_name}"
    Name = "${var.op_name}_route_table"
  }
}

resource "aws_route" "op_internet_access" {
  route_table_id        = "${aws_route_table.rt.id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${aws_internet_gateway.gw.id}"
}

resource "aws_route_table_association" "rt_assoc" {
  subnet_id      = "${aws_subnet.internal-subnet.id}"
  route_table_id = "${aws_route_table.rt.id}"
}

resource "aws_security_group" "ssh_from_company" {
  name = "${var.op_name}_ssh_from_company"
  description = "Allow incoming ssh connections"
  vpc_id = "${aws_vpc.op.id}"
  ingress  {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags {
    Op = "${var.op_name}"
    Name = "${var.op_name}_ssh_from_company"
  }
}

resource "aws_security_group" "internal" {
  name = "${var.op_name}_internal"
  description = "Allow subnet connectivity"
  vpc_id = "${aws_vpc.op.id}"
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

  tags {
    Op = "${var.op_name}"
    Name = "${var.op_name}_internal"
  }
}

resource "aws_security_group" "web_from_all" {
  name = "${var.op_name}_web_from_all"
  description = "Allow incoming http(s) connections"
  vpc_id = "${aws_vpc.op.id}"
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
  tags {
    Op = "${var.op_name}"
    Name = "${var.op_name}_web_from_all"
  }
}

resource "aws_security_group" "dns_from_all" {
  name = "${var.op_name}_dns_from_all"
  description = "Allow incoming dns connections"
  vpc_id = "${aws_vpc.op.id}"
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
  tags {
    Op = "${var.op_name}"
    Name = "${var.op_name}_dns_from_all"
  }
}


resource "aws_instance" "homebase" {
  ami = "${lookup(var.amis, "ubuntu18.04")}"
  # kali on 2018.3a breaks a lot of our puppet modules
  # 2019.1a is not an AMI due to AWS problems
  # https://twitter.com/TTimzen/status/1116799902648918016
  # ami = "${lookup(var.amis, "kali 2018.3a")}"
  instance_type = "t2.small"
  key_name = "${var.aws_key_name}"

  subnet_id = "${aws_subnet.internal-subnet.id}"
  private_ip = "192.168.0.10"
  associate_public_ip_address = true
  vpc_security_group_ids = [
    "${aws_security_group.ssh_from_company.id}",
    "${aws_security_group.internal.id}",
  ]
  tags {
    Op = "${var.op_name}"
    Name = "${format("%s_homebase", var.op_name)}"
  }

  # ubuntu = kali
  # ubuntu = ubuntu
  connection {
    type = "ssh"
    agent = "false"
    user = "ubuntu"
    private_key = "${local.private_key_contents}"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -c \"hostnamectl set-hostname homebase-${var.op_name}\""
    ]
  }

  provisioner "local-exec" {
    command = "bash -c \"cd $(git rev-parse --show-toplevel); tar -czf external/global/host-share/bootstrap-puppet.tgz .git\""
  }

  provisioner "local-exec" {
    command = "../global/generate_ssh_stanza.rb --opname ${var.op_name} --homebase_ip ${aws_instance.homebase.public_ip}"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/",
    ]
  }

  provisioner "file" {
    source = "../global/host-share/"
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../../puppet",
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../global/homebase",
    destination = "/tmp/host-share/"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/puppet/manifests",
      "ln -s /tmp/host-share/homebase/puppet/manifests/site.pp /tmp/host-share/puppet/manifests/site.pp",
      "if [ ! -L /etc/infra/site ]; then sudo mkdir -p /etc/infra && sudo ln -s external/global/homebase/puppet/manifests/site.pp /etc/infra/site; fi",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -e /tmp/host-share/setup.sh"
   ]
  }
}

resource "aws_instance" "proxies" {
  depends_on = [ "aws_instance.homebase" ]
  count = 2
  ami = "${lookup(var.amis, "ubuntu18.04")}"
  instance_type = "${local.instance_type}"
  key_name = "${var.aws_key_name}"

  subnet_id = "${aws_subnet.internal-subnet.id}"
  private_ip = "${format("192.168.2.%d", count.index + 11)}"
  associate_public_ip_address = true
  vpc_security_group_ids = [
    "${aws_security_group.internal.id}",
    "${aws_security_group.web_from_all.id}"
  ]
  tags {
    Op = "${var.op_name}"
    Name = "${format("%s_proxy-%02d", var.op_name, count.index + 1)}"
  }
  connection {
    type = "ssh"
    user = "ubuntu"
    host = "${format("192.168.2.%d", count.index + 11)}" # TODO: dedupe this
    private_key = "${local.private_key_contents}"
    agent = "false"
    bastion_host = "${aws_instance.homebase.public_ip}"
    bastion_user = "ubuntu"
    }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -c \"hostnamectl set-hostname proxy${format("%d",count.index)}-${var.op_name}\""
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/",
    ]
  }

  provisioner "file" {
    source = "../global/host-share/"
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../../puppet",
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../global/proxies",
    destination = "/tmp/host-share/"
  }


  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/puppet/manifests",
      "ln -s /tmp/host-share/proxies/puppet/manifests/site.pp /tmp/host-share/puppet/manifests/site.pp",
      "if [ ! -L /etc/infra/site ]; then sudo mkdir -p /etc/infra && sudo ln -s external/global/proxies/puppet/manifests/site.pp /etc/infra/site; fi",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -e /tmp/host-share/setup.sh"
    ]
  }
}

resource "aws_instance" "elk" {
  depends_on = [ "aws_instance.homebase" ]
  ami = "${lookup(var.amis, "ubuntu18.04")}"
  instance_type = "t2.medium"
  key_name = "${var.aws_key_name}"

  subnet_id = "${aws_subnet.internal-subnet.id}"
  private_ip = "192.168.1.13"
  associate_public_ip_address = true
  vpc_security_group_ids = [
    "${aws_security_group.internal.id}",
  ]
  tags {
    Op = "${var.op_name}"
    Name = "${format("%s_elk", var.op_name)}"
  }

  connection {
    type = "ssh"
    user = "ubuntu"
    agent = "false"
    host = "${aws_instance.elk.private_ip}"
    private_key = "${local.private_key_contents}"
    bastion_host = "${aws_instance.homebase.public_ip}"
    bastion_user = "ubuntu"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -c \"hostnamectl set-hostname elk-${var.op_name}\""
    ]
  }

  provisioner "remote-exec" {
  inline = [
    "mkdir -p /tmp/host-share/",
    ]
  }

  provisioner "file" {
    source = "../global/host-share/"
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../../puppet",
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../global/elkServer",
    destination = "/tmp/host-share/"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/puppet/manifests",
      "ln -s /tmp/host-share/elkServer/puppet/manifests/site.pp /tmp/host-share/puppet/manifests/site.pp",
      "if [ ! -L /etc/infra/site ]; then sudo mkdir -p /etc/infra && sudo ln -s external/global/elkServer/puppet/manifests/site.pp /etc/infra/site; fi",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -e /tmp/host-share/setup.sh"
    ]
  }

}

resource "aws_instance" "natlas" {
  depends_on = [ "aws_instance.homebase" ]
  ami = "${lookup(var.amis, "ubuntu18.04")}"
  instance_type = "${local.instance_type}"
  key_name = "${var.aws_key_name}"

  subnet_id = "${aws_subnet.internal-subnet.id}"
  private_ip = "192.168.1.14"
  associate_public_ip_address = true
  vpc_security_group_ids = [
    "${aws_security_group.internal.id}",
  ]
  tags {
    Op = "${var.op_name}"
    Name = "${format("%s_natlas", var.op_name)}"
  }

  connection {
    type = "ssh"
    user = "ubuntu"
    agent = "false"
    host = "${aws_instance.natlas.private_ip}"
    private_key = "${local.private_key_contents}"
    bastion_host = "${aws_instance.homebase.public_ip}"
    bastion_user = "ubuntu"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -c \"hostnamectl set-hostname natlas-${var.op_name}\""
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/",
    ]
  }

  provisioner "file" {
    source = "../global/host-share/"
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../../puppet",
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../global/natlas",
    destination = "/tmp/host-share/"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/puppet/manifests",
      "ln -s /tmp/host-share/natlas/puppet/manifests/site.pp /tmp/host-share/puppet/manifests/site.pp",
      "if [ ! -L /etc/infra/site ]; then sudo mkdir -p /etc/infra && sudo ln -s external/global/natlas/puppet/manifests/site.pp /etc/infra/site; fi",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -e /tmp/host-share/setup.sh"
    ]
  }

}
