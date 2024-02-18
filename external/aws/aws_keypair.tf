resource "aws_key_pair" "deployer" {
  key_name   = "deployer"
  public_key = tls_private_key.ssh_key.public_key_openssh
}