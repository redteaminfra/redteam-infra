# SSH Backflip For The Win(dows)

Microsoft has ported OpenSSH to Windows. We can now use SSH for C2 in Windows and because the binaries are 'official' they pass all the default Windows security checks.

In Windows 10 it's an optional feature.<br>
In Windows 11 the ssh client is included by default but the server has to be installed as an optional feature.

This script will generate a .zip file that contains ssh.exe and sshd.exe along with the necessary key pair files and configurations to do a backflip on either Win10 or Win11.<br>

## Configuration<br>
You can customize some aspects of the backflip for your operation. <br>
Edit the variables "backflipUser" and "spoofServer" in the "makebackflip.py" script.<br>
Those change the username user to connect back to the backflip server and add a "fake server name" to the victim's ssh_config file to mask the real backflip server hostname.<br>
By default the spoofServer is set to "totallynotmalicious.com". The idea is that if user or SOC look at the command line for ssh.exe it will appear to them as if ssh.exe is connecting to a benign host.


## Usage<br>
>     sudo python3 sshbackflip.py new --target victimhostname -os windows --spoofserver fakenameforc2

<br>
## References: <br>
- https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
- Linux manual pages.