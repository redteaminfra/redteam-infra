resource "oci_core_default_dhcp_options" "default-dhcp-options"  {
  manage_default_resource_id = oci_core_vcn.infra_vcn.default_dhcp_options_id
  options {
    type = "DomainNameServer"
    server_type = "CustomDnsServer"
    custom_dns_servers = [ "8.8.8.8", "4.4.4.4", "1.1.1.1" ]
  }
}
