# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "oci" {}
mock_provider "local" {}
mock_provider "tls" {}

variables {
  compartment_id          = "ocid1.compartment.oc1..example"
  ad_number               = 1
  region                  = "us-sanjose-1"
  engagement_name         = "profile-validation"
  config_file_profile     = "mock"
  ssh_allowed_cidr_ranges = ["192.0.2.10/32"]
  boot_volume_size_in_gbs = 512
}

override_data {
  target = data.oci_identity_availability_domain.ad
  values = {
    name = "mock-availability-domain"
  }
}

override_data {
  target = data.oci_core_images.ubuntu-version
  values = {
    images = [{ id = "ocid1.image.oc1..example" }]
  }
}

run "standard_rti_production_profile" {
  command = plan

  variables {
    is_production             = true
    production_homebase_shape = "BM.Standard3.64"
    homebase_shape            = "VM.Standard.E4.Flex"
    homebase_ocpus            = 16
    homebase_memory_in_gbs    = 512
    proxy_shape               = "VM.Standard.E4.Flex"
    proxy_ocpus               = 2
    proxy_memory_in_gbs       = 32
    proxy_count               = 2
    elk_shape                 = "VM.Standard.E4.Flex"
    elk_ocpus                 = 2
    elk_memory_in_gbs         = 32
  }

  assert {
    condition     = oci_core_instance.homebase.shape == "BM.Standard3.64" && length(oci_core_instance.homebase.shape_config) == 0
    error_message = "Production homebase must use BM.Standard3.64 without Flex shape_config."
  }

  assert {
    condition     = length(oci_core_instance.proxy) == 2 && oci_core_instance.proxy[0].shape_config[0].ocpus == 2 && oci_core_instance.proxy[0].shape_config[0].memory_in_gbs == 32
    error_message = "Standard RTI proxies must receive the independent 2 OCPU / 32 GiB Flex allocation."
  }

  assert {
    condition     = oci_core_instance.elk.shape_config[0].ocpus == 2 && oci_core_instance.elk.shape_config[0].memory_in_gbs == 32
    error_message = "ELK must receive its independent 2 OCPU / 32 GiB Flex allocation."
  }
}

run "dev_infra_profile" {
  command = plan

  variables {
    is_production          = false
    homebase_shape         = "VM.Standard.E4.Flex"
    homebase_ocpus         = 16
    homebase_memory_in_gbs = 512
    proxy_shape            = "VM.Standard.E4.Flex"
    proxy_ocpus            = 2
    proxy_memory_in_gbs    = 32
    proxy_count            = 1
    elk_shape              = "VM.Standard.E4.Flex"
    elk_ocpus              = 2
    elk_memory_in_gbs      = 32
  }

  assert {
    condition     = oci_core_instance.homebase.shape_config[0].ocpus == 16 && oci_core_instance.homebase.shape_config[0].memory_in_gbs == 512
    error_message = "Dev Infra homebase must receive the 16 OCPU / 512 GiB Flex allocation."
  }

  assert {
    condition     = length(oci_core_instance.proxy) == 1
    error_message = "The Dev Infra fixture must create one proxy."
  }
}

run "production_flex_homebase_profile" {
  command = plan

  variables {
    is_production             = true
    production_homebase_shape = "VM.Standard.E4.Flex"
    homebase_shape            = "VM.Standard2.1"
    homebase_ocpus            = 16
    homebase_memory_in_gbs    = 512
    proxy_shape               = "VM.Standard2.1"
    proxy_count               = 1
    elk_shape                 = "VM.Standard2.1"
  }

  assert {
    condition     = oci_core_instance.homebase.shape == "VM.Standard.E4.Flex" && oci_core_instance.homebase.shape_config[0].ocpus == 16 && oci_core_instance.homebase.shape_config[0].memory_in_gbs == 512
    error_message = "A configurable production Flex homebase must receive its declared OCPU and memory allocation."
  }
}

run "flex_homebase_requires_complete_capacity_pair" {
  command = plan

  variables {
    is_production          = false
    homebase_shape         = "VM.Standard.E4.Flex"
    homebase_ocpus         = 16
    homebase_memory_in_gbs = null
    proxy_shape            = "VM.Standard2.1"
    proxy_count            = 1
    elk_shape              = "VM.Standard2.1"
  }

  expect_failures = [oci_core_instance.homebase]
}

run "flex_proxy_requires_complete_capacity_pair" {
  command = plan

  variables {
    is_production       = false
    homebase_shape      = "VM.Standard2.1"
    proxy_shape         = "VM.Standard.E4.Flex"
    proxy_ocpus         = 2
    proxy_memory_in_gbs = null
    proxy_count         = 1
    elk_shape           = "VM.Standard2.1"
  }

  expect_failures = [oci_core_instance.proxy]
}

run "flex_elk_requires_complete_capacity_pair" {
  command = plan

  variables {
    is_production     = false
    homebase_shape    = "VM.Standard2.1"
    proxy_shape       = "VM.Standard2.1"
    proxy_count       = 1
    elk_shape         = "VM.Standard.E4.Flex"
    elk_ocpus         = 2
    elk_memory_in_gbs = null
  }

  expect_failures = [oci_core_instance.elk]
}

run "legacy_fixed_shapes_remain_valid" {
  command = plan

  variables {
    is_production  = false
    homebase_shape = "VM.Standard2.1"
    proxy_shape    = "VM.Standard2.1"
    proxy_count    = 2
    elk_shape      = "VM.Standard2.1"
  }

  assert {
    condition = (
      length(oci_core_instance.homebase.shape_config) == 0 &&
      length(oci_core_instance.proxy[0].shape_config) == 0 &&
      length(oci_core_instance.elk.shape_config) == 0
    )
    error_message = "Legacy fixed shapes must remain valid without Flex capacity variables."
  }
}
