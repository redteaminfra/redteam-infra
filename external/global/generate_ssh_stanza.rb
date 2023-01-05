#!/usr/bin/env ruby
# Copyright (c) 2022, Oracle and/or its affiliates.

require 'optparse'

options = {}
OptionParser.new do |opt|
  opt.on('--opname OPNAME') { |o| options[:opname] = o }
  opt.on('--homebase_ip HOMEBASE_IP') { |o| options[:homebase_ip] = o }
end.parse!

# https://stackoverflow.com/questions/1541294/how-do-you-specify-a-required-switch-not-argument-with-ruby-optionparser/1542658#1542658
begin
  mandatory = [:homebase_ip, :opname]
  missing = mandatory.select{ |param| options[param].nil? }
  raise OptionParser::MissingArgument, missing.join(', ') unless missing.empty?
rescue OptionParser::ParseError => e
  puts e
  puts options
  exit
end

homebase_ip = options[:homebase_ip]
opname = options[:opname]

stanza =
<<SSH
Host homebase-#{opname}
     Hostname #{homebase_ip}
     # Uncomment AddressFamily if you have WSL errors to force ipv4
     ## AddressFamily inet
     # Etherpad
     ## LocalForward 9001 127.0.0.1:9001
     # Mythic
     LocalForward 7443 127.0.0.1:7443
     # Change 59xx to your VNC Port and uncomment this forward. Your UID is found in sshkeys users.json
     ## Your port number is (5900 + (UID - 6000) + 1)
     ## LocalForward 5901 127.0.0.1:59xx

Host proxy01-#{opname}
    Hostname proxy01-#{opname}.infra.redteam
    ProxyJump homebase-#{opname}

Host proxy02-#{opname}
    Hostname proxy02-#{opname}.infra.redteam
    ProxyJump homebase-#{opname}

Host elk-#{opname}
     Hostname elk-#{opname}.infra.redteam
     ProxyJump homebase-#{opname}
     LocalForward 5601 192.168.1.13:5601
SSH

stanzafile = "homebase-#{opname}"
File.open(stanzafile, 'w') do |file|
  file.write(stanza)
end

STDOUT.puts <<INSTRUCTIONS
Copy the generated file (#{stanzafile}) into you ssh config like this:
cat #{stanzafile} >> ~/.ssh/config
INSTRUCTIONS
