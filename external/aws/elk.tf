resource "aws_instance" "elk" {
  depends_on                  = [ aws_instance.homebase ]
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.elk_shape
  key_name                    = aws_key_pair.deployer.key_name
  subnet_id                   = aws_subnet.infra.id
  private_ip                  = "192.168.1.13"
  associate_public_ip_address = true

  vpc_security_group_ids = [
    aws_security_group.internal.id,
  ]

  root_block_device {
    volume_type = "standard"
    volume_size = var.boot_volume_size_in_gbs
  }

  tags = {
    Op   = var.engagement_name
    Name = "elk-${var.engagement_name}"
  }

  lifecycle {
    ignore_changes = [
      ami,  # Ignore changes to the AMI, you don't want TF to destroy resources if it is updated
    ]
  }
}