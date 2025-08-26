# SSH Backflip Internals
This doc explains the internal workings of sshbackflips and why the code is organized the way it is.<br>
## Oraganization
### sshbackflip.py <br>
is the main script that users of sshbackflip will interact with. It takes care of parsing arguments instantiating "server" and "victim" objects and calling the appropriate payload generators according to the user's request.<br><br>
### settings.py <br>
is the centralized place where we store settings and global variables that we want to share between many modules.<br><br>
### core.py<br>
 contains classes and functions that are useful to many modules of sshbackflips; such as the Victim class and the Server class, random word generators, encoders, etc.<br><br>
### linux.py, macos.py and windows.py <br>
contain all the logic to generate new payloads using templates found in the subdirectories with the corresponding OS name. <br> Each one contains a function like:<br>
`makebackflip(backflipServer, victim, args)` <br>
The makebackflip() function will be called by sshbackflip.py to request the creation of a new payload.<br>
- backflipServer is an object that represents the C2 server and has attributes such as IP, FQDN, port, callback user, hostkey, etc.<br>
- victim is an object that represents the victim for which we are creating the payload. It has attributes such as username, hostname, public/private key for the backflip ssh connection and for login to the victim host, assigned port (so each victim's ssh listener is mapped to a different port on the C2 server) <br>
- args is a list of additional arguments each particular generator may need. <br>
