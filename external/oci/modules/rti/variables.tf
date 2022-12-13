variable "network_protocol" {
  default = {
    "tcp"  = "6"
    "icmp" = "1"
    "udp"  = "17"
  }
}

variable "avail_dom" {
  default = "0" //0 - AD1, 1 - AD2, 2 - AD3
}

variable "region" {
}

variable "compartment_id" {
}

// TODO: revisit the Image ID / Shape / Host names defaults so we don't burden the callers

variable "infra_shape" {
  default = "VM.Standard2.1"
}

variable "vcn_cidr_block" {
  default = "192.168.0.0/16"
}

variable "infra_subnet_cidr" {
  default = "192.168.0.0/24"
}

variable "utility_cidr" {
  default = "192.168.1.0/24"
}

variable "proxy_cidr" {
  default = "192.168.2.0/24"
}

variable "proxy_name" {
  default = "proxy"
}

variable "proxy_shape" {
  default = "VM.Standard2.1"
}

variable "ssh_provisioning_public_key" {
}

variable "ssh_provisioning_private_key" {
}

# Canonical-Ubuntu-18.04-2019.09.18-0 us-phoenix-1
variable "ubuntu_image_id" {
  type = map(string)
  default = {
    af-johannesburg-1 = "ocid1.image.oc1.af-johannesburg-1.aaaaaaaaapb5rh5nfpqdo6qmja46eiedtp44afxonduof5w54nv6m6tnxjla"
    ap-chuncheon-1 = "ocid1.image.oc1.ap-chuncheon-1.aaaaaaaafa3i7ucvpxaw7yct3d4yckhq6g6v2pnk2zkmmxz5qbvb4pzgbqsa"
    ap-hyderabad-1 = "ocid1.image.oc1.ap-hyderabad-1.aaaaaaaanvj7owsyhqs6qhlbpbhzketnhuky3vzezzhgcpms55tlsamb6vea"
    ap-melbourne-1 = "ocid1.image.oc1.ap-melbourne-1.aaaaaaaaqgcebofpuo7fi5zygrztvxshwimcnd2kas24ntbzb5fvvrzlcrha"
    ap-mumbai-1 = "ocid1.image.oc1.ap-mumbai-1.aaaaaaaakbwi2jeiezzs3yxovwk63hslknusauzqvbmrxwys4p2ve7mja34q"
    ap-osaka-1 = "ocid1.image.oc1.ap-osaka-1.aaaaaaaapzxbek4yn3fmsdf2q533fjgjrxkmibvftn7axq5piuhgernjneua"
    ap-seoul-1 = "ocid1.image.oc1.ap-seoul-1.aaaaaaaadzoqla6wakumfcqfx44g7lts3vqkeluhnll6exlvjdrgax7yexhq"
    ap-singapore-1 = "ocid1.image.oc1.ap-singapore-1.aaaaaaaajgpwm64hfpqbaz4vmjdwphavz2eijm4aqblh5k6vrgkw73pw3ljq"
    ap-sydney-1 = "ocid1.image.oc1.ap-sydney-1.aaaaaaaapdv44pzfh4dy2gpcwuagbykcrxmps5g3ddheusj25j3qp4yp5p2a"
    ap-tokyo-1 = "ocid1.image.oc1.ap-tokyo-1.aaaaaaaaiqnzylthf6siyhwrnwu7fzci2clbp4rpdtuok6byikb727nklc5q"
    ca-montreal-1 = "ocid1.image.oc1.ca-montreal-1.aaaaaaaagqxr2rgiz3xjr7cysscvp6wnkamgjfgbcerk422rgcputae6rg4q"
    ca-toronto-1 = "ocid1.image.oc1.ca-toronto-1.aaaaaaaat6wdszxldcx55zuhmn6csstbhw3ulx2qn2m36kmw2sgr2y6a4cyq"
    eu-amsterdam-1 = "ocid1.image.oc1.eu-amsterdam-1.aaaaaaaairwvce5rrm4xkybuloomnsj55rnfqqffzwmgdz6zli7ynr7yt2eq"
    eu-frankfurt-1 = "ocid1.image.oc1.eu-frankfurt-1.aaaaaaaavcrpbwmm75t6azhxgepxah6vigiwwvruti3gj2frhuxnvhzn3e5a"
    eu-marseille-1 = "ocid1.image.oc1.eu-marseille-1.aaaaaaaalbfjwdvxtjnctivhvhd35ybzxog636avqhhupylj62ss7jqg3eka"
    eu-milan-1 = "ocid1.image.oc1.eu-milan-1.aaaaaaaa7vgsz4wbewx45havrgrkq7pynn5634zc54u7pnyp3noaoeyyxkba"
    eu-stockholm-1 = "ocid1.image.oc1.eu-stockholm-1.aaaaaaaaom2uzwytlkygx24vfsut2slyb5plogkj6zvpi7qsacgas6kmj7ta"
    eu-zurich-1 = "ocid1.image.oc1.eu-zurich-1.aaaaaaaajnd3h3nq2hotdp4hctcfgib5aaao6dx43jr6zu65bgtrour6b24q"
    il-jerusalem-1 = "ocid1.image.oc1.il-jerusalem-1.aaaaaaaad74lwx5ddqjinimnzbygic6ohydm272bsw2kzgxhrebge4gg7gxq"
    me-abudhabi-1 = "ocid1.image.oc1.me-abudhabi-1.aaaaaaaazi7yclew5mz3z2722maexivzjtlkkqjhi7skjxyb4yiick7e7prq"
    me-dubai-1 = "ocid1.image.oc1.me-dubai-1.aaaaaaaal6oif7ku4t2bjdfnleqhzyiodm66tjvxcz5m5sfyvfs23exagyea"
    me-jeddah-1 = "ocid1.image.oc1.me-jeddah-1.aaaaaaaajdkpe2rfvxmqztnnocrmzcjl4jt6uwgtnh4rq2ne5ht3rqd2f2eq"
    sa-santiago-1 = "ocid1.image.oc1.sa-santiago-1.aaaaaaaaovioordeomhpi73yxovfafcfngv4mv6qeuoe4otru42fn6nostca"
    sa-saopaulo-1 = "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaamp6xsr5asrv4fquaogmv3lb3sttua4ohwyyqn4s5g47jckd2e3ma"
    sa-vinhedo-1 = "ocid1.image.oc1.sa-vinhedo-1.aaaaaaaakgamg7r5bo55dcplbauqcvk2tbtsol3qtgmoubqdc22u66shmu5a"
    uk-cardiff-1 = "ocid1.image.oc1.uk-cardiff-1.aaaaaaaagvqk2zbiievaa7e6r5eeeh3ysxdmix2wuz3tljyzgx6jcucb462a"
    uk-london-1 = "ocid1.image.oc1.uk-london-1.aaaaaaaafjzdmedd2xw2preuca6b63l6bng5pflfwjw6lb7xwpjyh7ovbqva"
    us-ashburn-1 = "ocid1.image.oc1.iad.aaaaaaaamc2xy64p4r4tcwjy26ksdkehrdrzjcacw4upaq7fnqict55as4kq"
    us-phoenix-1 = "ocid1.image.oc1.phx.aaaaaaaan3xenf5nz6jgwmseebf2moledl23zsnwekvqok2u3kh77fhketeq"
    us-sanjose-1 = "ocid1.image.oc1.us-sanjose-1.aaaaaaaarlhoz4n2z2v6vbml3yausxd3jfp4i642ofr2kmafhkjm6fwmq2dq"
  }
}

# set to ubuntu for now
variable "kali_image_id" {
  type = map(string)
  default = {
    af-johannesburg-1 = "ocid1.image.oc1.af-johannesburg-1.aaaaaaaaapb5rh5nfpqdo6qmja46eiedtp44afxonduof5w54nv6m6tnxjla"
    ap-chuncheon-1 = "ocid1.image.oc1.ap-chuncheon-1.aaaaaaaafa3i7ucvpxaw7yct3d4yckhq6g6v2pnk2zkmmxz5qbvb4pzgbqsa"
    ap-hyderabad-1 = "ocid1.image.oc1.ap-hyderabad-1.aaaaaaaanvj7owsyhqs6qhlbpbhzketnhuky3vzezzhgcpms55tlsamb6vea"
    ap-melbourne-1 = "ocid1.image.oc1.ap-melbourne-1.aaaaaaaaqgcebofpuo7fi5zygrztvxshwimcnd2kas24ntbzb5fvvrzlcrha"
    ap-mumbai-1 = "ocid1.image.oc1.ap-mumbai-1.aaaaaaaakbwi2jeiezzs3yxovwk63hslknusauzqvbmrxwys4p2ve7mja34q"
    ap-osaka-1 = "ocid1.image.oc1.ap-osaka-1.aaaaaaaapzxbek4yn3fmsdf2q533fjgjrxkmibvftn7axq5piuhgernjneua"
    ap-seoul-1 = "ocid1.image.oc1.ap-seoul-1.aaaaaaaadzoqla6wakumfcqfx44g7lts3vqkeluhnll6exlvjdrgax7yexhq"
    ap-singapore-1 = "ocid1.image.oc1.ap-singapore-1.aaaaaaaajgpwm64hfpqbaz4vmjdwphavz2eijm4aqblh5k6vrgkw73pw3ljq"
    ap-sydney-1 = "ocid1.image.oc1.ap-sydney-1.aaaaaaaapdv44pzfh4dy2gpcwuagbykcrxmps5g3ddheusj25j3qp4yp5p2a"
    ap-tokyo-1 = "ocid1.image.oc1.ap-tokyo-1.aaaaaaaaiqnzylthf6siyhwrnwu7fzci2clbp4rpdtuok6byikb727nklc5q"
    ca-montreal-1 = "ocid1.image.oc1.ca-montreal-1.aaaaaaaagqxr2rgiz3xjr7cysscvp6wnkamgjfgbcerk422rgcputae6rg4q"
    ca-toronto-1 = "ocid1.image.oc1.ca-toronto-1.aaaaaaaat6wdszxldcx55zuhmn6csstbhw3ulx2qn2m36kmw2sgr2y6a4cyq"
    eu-amsterdam-1 = "ocid1.image.oc1.eu-amsterdam-1.aaaaaaaairwvce5rrm4xkybuloomnsj55rnfqqffzwmgdz6zli7ynr7yt2eq"
    eu-frankfurt-1 = "ocid1.image.oc1.eu-frankfurt-1.aaaaaaaavcrpbwmm75t6azhxgepxah6vigiwwvruti3gj2frhuxnvhzn3e5a"
    eu-marseille-1 = "ocid1.image.oc1.eu-marseille-1.aaaaaaaalbfjwdvxtjnctivhvhd35ybzxog636avqhhupylj62ss7jqg3eka"
    eu-milan-1 = "ocid1.image.oc1.eu-milan-1.aaaaaaaa7vgsz4wbewx45havrgrkq7pynn5634zc54u7pnyp3noaoeyyxkba"
    eu-stockholm-1 = "ocid1.image.oc1.eu-stockholm-1.aaaaaaaaom2uzwytlkygx24vfsut2slyb5plogkj6zvpi7qsacgas6kmj7ta"
    eu-zurich-1 = "ocid1.image.oc1.eu-zurich-1.aaaaaaaajnd3h3nq2hotdp4hctcfgib5aaao6dx43jr6zu65bgtrour6b24q"
    il-jerusalem-1 = "ocid1.image.oc1.il-jerusalem-1.aaaaaaaad74lwx5ddqjinimnzbygic6ohydm272bsw2kzgxhrebge4gg7gxq"
    me-abudhabi-1 = "ocid1.image.oc1.me-abudhabi-1.aaaaaaaazi7yclew5mz3z2722maexivzjtlkkqjhi7skjxyb4yiick7e7prq"
    me-dubai-1 = "ocid1.image.oc1.me-dubai-1.aaaaaaaal6oif7ku4t2bjdfnleqhzyiodm66tjvxcz5m5sfyvfs23exagyea"
    me-jeddah-1 = "ocid1.image.oc1.me-jeddah-1.aaaaaaaajdkpe2rfvxmqztnnocrmzcjl4jt6uwgtnh4rq2ne5ht3rqd2f2eq"
    sa-santiago-1 = "ocid1.image.oc1.sa-santiago-1.aaaaaaaaovioordeomhpi73yxovfafcfngv4mv6qeuoe4otru42fn6nostca"
    sa-saopaulo-1 = "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaamp6xsr5asrv4fquaogmv3lb3sttua4ohwyyqn4s5g47jckd2e3ma"
    sa-vinhedo-1 = "ocid1.image.oc1.sa-vinhedo-1.aaaaaaaakgamg7r5bo55dcplbauqcvk2tbtsol3qtgmoubqdc22u66shmu5a"
    uk-cardiff-1 = "ocid1.image.oc1.uk-cardiff-1.aaaaaaaagvqk2zbiievaa7e6r5eeeh3ysxdmix2wuz3tljyzgx6jcucb462a"
    uk-london-1 = "ocid1.image.oc1.uk-london-1.aaaaaaaafjzdmedd2xw2preuca6b63l6bng5pflfwjw6lb7xwpjyh7ovbqva"
    us-ashburn-1 = "ocid1.image.oc1.iad.aaaaaaaamc2xy64p4r4tcwjy26ksdkehrdrzjcacw4upaq7fnqict55as4kq"
    us-phoenix-1 = "ocid1.image.oc1.phx.aaaaaaaan3xenf5nz6jgwmseebf2moledl23zsnwekvqok2u3kh77fhketeq"
    us-sanjose-1 = "ocid1.image.oc1.us-sanjose-1.aaaaaaaarlhoz4n2z2v6vbml3yausxd3jfp4i642ofr2kmafhkjm6fwmq2dq"
  }
}

variable "instance_user" {
  default = "ubuntu"
}

variable "homebase_user" {
  default = "ubuntu"
}

variable "op_name" {
}

variable "preserve_boot_volume" {
  default = "false"
}

variable "provisioners_dir" {
  default = "provisioners"
}

variable "default_image_size_gbs" {
  default = "512"
}
