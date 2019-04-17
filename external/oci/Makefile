%.tf: %.tf.erb
	ruby generate_network_seclists.rb $< $@

all: modules/rti/network_seclists.tf seclists.json
