module "aws_sketch" {
    source = "./modules/aws/sketch"
    providers = {
        aws = aws 
    }
    engagment_name = var.engagment_name
    ssh_config_path = var.ssh_config_path
    # other neccessary variables if needed