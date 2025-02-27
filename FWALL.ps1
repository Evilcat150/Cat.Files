param(
[String]$ScriptArgs = @("")
)
$ErrorActionPreference = "SilentlyContinue"


$Argsarray = $ScriptArgs -Split ";"
if($Argsarray.Count -lt 2){
    Write-Host "Needs 2 arguments"
    break
}
$Dispatcher = $Argsarray[0]; 
$Localnetwork = $Argsarray[1];

$TeamNumber = "7";
$JumpIP = "10.$TeamNumber.1.1";
$IpAddress = "192.168.$TeamNumber.1" #(Get-NetIPAddress |Where-Object {$_.AddressState -eq 'Preferred' -and $_.ValidLifetime -lt '24:00:00'}).IPAddress

netsh advfirewal export "C:\Firewall.wfw"


if(-not(Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue) -or -not(Get-Command Get-ScheduledTask)){
   if(schtasks /Query /TN  FWRevert){

        schtasks /delete /tn FWRevert /f
        $startTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
        schtasks /create /tn "FWRevert" /tr "netsh advfirewall import 'C:\Firewall.wfw'" /ru "NT AUTHORITY\SYSTEM" /sc once /st $startTime /f 
    }

    else{

        $startTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
        schtasks /create /tn "FWRevert" /tr "netsh advfirewall import 'C:\Firewall.wfw'" /ru "NT AUTHORITY\SYSTEM" /sc once /st $startTime /f 
    }
        
    netsh advfirewall set allprofiles state off

    cmd.exe /c "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"


    netsh advfirewall firewall delete rule name=all

    netsh advfirewall firewall add rule name="WINRM 80" dir=in protocol=TCP localport=80 remoteip=$Dispatcher action=allow
    netsh advfirewall firewall add rule name="WINRM 5985" dir=in protocol=TCP localport=5985 remoteip=$Dispatcher action=allow
    netsh advfirewall firewall add rule name="WINRM 5986" dir=in protocol=TCP localport=5986 remoteip=$Dispatcher action=allow

    netsh advfirewall firewall add rule name="Remote Desktop" dir=in protocol=TCP localport=3389 remoteip=$Dispatcher action=allow

    netsh advfirewall firewall add rule name="Local Network" dir=in protocol=TCP  remoteip=$Localnetwork action=allow
    netsh advfirewall firewall add rule name="Local Network" dir=out protocol=TCP  remoteip=$Localnetwork action=allow

    if($Notnats -ne "NOTNATS"){
        netsh advfirewall firewall add rule name="NotNats" dir=in protocol=any remoteip=$Notnats action=allow
        netsh advfirewall firewall add rule name="NotNats" dir=out protocol=any remoteip=$Notnats action=allow
    }

    netsh advfirewall set allprofiles state on
}

else{
   if(Get-ScheduledTask -TaskName "FWRevert" -ErrorAction SilentlyContinue){

        Unregister-ScheduledTask -TaskName "FWRevert" -Confirm:$false
        $taskaction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "netsh advfirewal import 'C:\Firewall.wfw'"
        $starttime = (Get-Date).AddMinutes(5)
        $trigger = New-ScheduledTaskTrigger -At $starttime -Once
        Register-ScheduledTask -Action $taskaction -Trigger $trigger -TaskName FWRevert -User "NT AUTHORITY\SYSTEM" -Force
    }

    else{
    
       $taskaction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "netsh advfirewal import 'C:\Firewall.wfw'"
       $starttime = (Get-Date).AddMinutes(5)
       $trigger = New-ScheduledTaskTrigger -At $starttime -Once
       Register-ScheduledTask -Action $taskaction -Trigger $trigger -TaskName FWRevert -Description "Reverts Firewall" -User "NT AUTHORITY\SYSTEM" -Force
    }


    Set-NetFirewallProfile -All -Enabled False
    
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block -Name Domain -Enabled False
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block -Name Private -Enabled False
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block -Name Public -Enabled False

    Remove-NetFirewallRule -All 



    New-NetFirewallRule -DisplayName "WinRM" -Direction Inbound -Protocol TCP -LocalPort 80,5985,5986 -RemoteAddress $Dispatcher
    New-NetFirewallRule -DisplayName "Datadog" -Direction Outbound  -Program "C:\Program Files\Datadog Agent\bin\agent.exe"


    # Domain Controller
    if($IpAddress -eq "10.$TeamNumber.1.1"){
        New-NetFirewallRule -DisplayName "Local10DNS" -Direction Inbound -Protocol TCP -LocalPort 53 -Program "C:\Windows\System32\dns.exe" -RemoteAddress "10.$TeamNumber.1.0/24"
        New-NetFirewallRule -DisplayName "Local192DNS" -Direction Inbound -Protocol TCP -LocalPort 53 -Program "C:\Windows\System32\dns.exe" -RemoteAddress "192.168.$TeamNumber.0/24"
        New-NetFirewallRule  -DisplayName "Remote Desktop" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $JumpIP
    }

    # HTTPS server
    if($IpAddress -eq "10.$TeamNumber.1.2"){
        New-NetFirewallRule -DisplayName "HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Program "C:\nginx\nginx.exe"
        New-NetFirewallRule  -DisplayName "Remote Desktop" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $JumpIP
    }
    
    # WINRM Box
    if($IpAddress -eq "10.$TeamNumber.1.3"){
        New-NetFirewallRule -DisplayName "WinRM" -Direction Inbound -Protocol TCP -LocalPort 80,5985,5986
        New-NetFirewallRule  -DisplayName "Remote Desktop" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $JumpIP
    }


    if($IpAddress -eq "192.168.$TeamNumber.1"){
        New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound -Protocol TCP -LocalPort 80
        New-NetFirewallRule  -DisplayName "Remote Desktop" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $JumpIP
    }


    #New-NetFirewallRule  -DisplayName "Remote Desktop" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $Dispatcher



    Set-NetFirewallProfile -All -Enabled true



}
