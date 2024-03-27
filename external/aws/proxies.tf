resource "aws_instance" "proxy" {
  depends_on                  = [ aws_instance.homebase ]
  count                       = var.proxy_count
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.proxy_shape
  key_name                    = aws_key_pair.deployer.key_name
  subnet_id                   = aws_subnet.infra.id
  private_ip                  = format("192.168.2.%d", count.index + 11)
  associate_public_ip_address = true

  root_block_device {
    volume_type = "standard"
    volume_size = var.boot_volume_size_in_gbs
  }

  vpc_security_group_ids = [
    aws_security_group.internal.id,
    aws_security_group.web_from_all.id
  ]

  metadata_options {
    http_tokens = "required" # enable imds v2
  }

  tags = {
    Op   = var.engagement_name
    Name = "proxy${format("%02g", count.index + 1)}-${var.engagement_name}"
  }

  lifecycle {
    ignore_changes = [
      ami,  # Ignore changes to the AMI, you don't want TF to destroy resources if it is updated
    ]
  }
}
