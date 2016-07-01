Function Wake-CMDevice {

<#
  .SYNOPSIS
    Sends a "Magic Packet" to wake a Configuration Manager client.  Queries a local CM server for Network Adapter details.
    This functionality is highly dependent on an accurate Hardware Inventory in SCCM.
  .PARAMETER ComputerName
    The hostname of the device that you want to wake up
  .PARAMETER Port
    Allows you to specify the port you want to use for the UDP WOL packet
  .PARAMETER Broadcast
    Switch parameter that allows you to specify a broadcast directed WOL packet
  .PARAMETER Unicast
    Switch parameter that allows you to specify a unicast directed WOL package
  .PARAMETER QueryDNS
    Switch parameter that indicates you would like the function to query local DNS for the computer's network information instead
    of getting the information from SCCM's network adapter information.
  .EXAMPLE
    Wake-CMDevice -ComputerName IT-TEST-7006
      Will attempt to send a "Magic Packet" to a computer named "IT-TEST-7006" based on the network information queried from SCCM
  .NOTES
    This function needs to be called from a Configuration Manager client machine in order to be able to query the Configuration Manager
    server.  Depending on your network configuration

#>

[CmdletBinding(DefaultParametersetName='Broadcast')]
PARAM(
    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]$ComputerName,
    
    [Parameter()]
    [uint32]$Port = 9,

    [Parameter(ParameterSetName='Broadcast')]
    [switch]$Broadcast,

    [Parameter(ParameterSetName='Unicast')]
    [switch]$Unicast,

    [Parameter()]
    [switch]$QueryDNS
)

    if( $QueryDNS.IsPresent ) {
        
        Try {

            $DHCPServerName = Get-DhcpServerInDC | Select-Object -ExpandProperty DnsName

            $ip = [System.Net.IPAddress]($ComputerName | Get-IPFromHostEntry)
            $mac = Get-DhcpServerv4Lease -ComputerName $DHCPServerName -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ClientId

            if( $mac ) {
                
                Send-WakeOnLanPacket -MACAddress $mac -IPAddress $ip
                Write-Verbose "DNS Query Selected.  Sending WOL Packet to $ip (MAC: $mac)"

            }

            else {

                $errMsg = "Unable to query DHCP Lease, the computer might have a static IP or DHCP reservation. Try running the command without the -QueryDNS switch"
                Write-Error -Message $errMsg -Category ObjectNotFound

            } 


        }

        Catch {

            Write-Error $_

        }


    }

    else {
    
        #region Query SCCM

       $networkAdapters = $ComputerName | Get-SCCMNetworkAdapterConfiguration
    
        if(!$networkAdapters) {
            Write-Verbose "WARNING:  No network adapters found for $ComputerName"
        }

        foreach ($nic in $networkAdapters){

            ### Sometimes there is more than one IP address assigned to a NIC.  This usually happens if IPv6 is enabled.
            ### The IPv4 address is always first, so we want element 0
            $ip = $nic.IPAddress.Split(",")[0]
            $mac = $nic.MACAddress
           
            Try{

                ### Which type of WOL are we using?  Subnet Directed Broadcast or Unicast?
                switch ($PSCmdlet.ParameterSetName) {
            
                    'Broadcast'
                        {

                            ### If we're using broadcast, we need to calculate the subnet's broadcast address
                            $subnet = $nic.IPSubnet.Split(",")[0]
                            $broadcastIP = Get-BroadcastSubnet -IPAddress $ip -IPSubnet $subnet
                            ### Send the WOL packet to the subnet's broadcast address
                            Send-WakeOnLanPacket -MACAddress $mac -IPAddress $broadcastIP

                            Write-Verbose "Sending Broadcast WOL packet for $ComputerName (IP: $ip) to $broadcastIP"
                        }
                
                    'Unicast'
                        {
            
                            ### If we're using unicast, we use the target's IP address.  This requires the closest switch/router to have
                            ### a recent ARP entry for the device or "ARP offload" to be configured and working for the client network adapter.
                            Send-WakeOnLanPacket -MACAddress $mac -IPAddress $ip

                            Write-Verbose "Sending Unicast WOL packet for $ComputerName to $ip"

                        }

            
                }
        
            }
        
            Catch {
        
                Write-Error $_
        
            }

        }
        #endregion Query SCCM

    }

}

Function Get-SCCMNetworkAdapterConfiguration {

[CmdletBinding()]
PARAM(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$ComputerName
)

    $smsAuthority = Get-WmiObject -Class SMS_Authority -Namespace root\ccm
    $serverName = $smsAuthority.CurrentManagementPoint
    Write-Verbose "Current Management Point: $serverName"
    
    $siteCode = $smsAuthority.Name.Split(":")[1]
    $sccmNamespace = "root\sms\site_$($siteCode)"
    $wmiQuery = "SELECT ResourceID FROM SMS_R_System WHERE Name = '$ComputerName'"
    $resourceID = (Get-WmiObject -Query $wmiQuery -Namespace $sccmNamespace -ComputerName $serverName).ResourceID
    Write-Verbose "SCCM Resource ID for $($ComputerName): $resourceID"

    $wmiQuery = "SELECT IPAddress,MACAddress,IPSubnet FROM SMS_G_System_NETWORK_ADAPTER_CONFIGURATION WHERE ResourceID='$resourceID' AND MACAddress IS NOT NULL AND IPAddress IS NOT NULL"
    $networkAdapters = Get-WmiObject -Query $wmiQuery -Namespace $sccmNamespace -ComputerName $serverName
    
    return $networkAdapters
}

Function Get-BroadcastSubnet {

[CmdletBinding()]
PARAM(
    [Parameter(Mandatory=$true)]
    [ValidateScript( { $_ -match [System.Net.IPAddress]$_ } ) ]
    [String]$IPAddress,
    
    [Parameter(Mandatory=$true)]
    [ValidateScript( { $_ -match [System.Net.IPAddress]$_ } ) ]
    [String]$IPSubnet 
)

    $ip = [System.Net.IPAddress]$IPAddress
    $subnet = [System.Net.IPAddress]$IPSubnet
    $broadcast = [System.Net.IPAddress]::Broadcast

    $subnetBroadcast = [System.Net.IPAddress]( $broadcast.Address -bxor $subnet.Address -bor $ip.Address )
    
    return $subnetBroadcast

}

Function Get-IPFromHostEntry {

[CmdletBinding()]
PARAM(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$ComputerName
)

    $hostEntry = [System.Net.Dns]::GetHostEntry($ComputerName)
    $ipAddress = $HostEntry.AddressList | Where-Object -Property AddressFamily -EQ -Value "InterNetwork" | Select-Object -ExpandProperty IPAddressToString
    return $ipAddress

}

Function Send-WakeOnLanPacket {

[CmdletBinding()]
PARAM(
    [Parameter(Mandatory=$true)]
    [String]$MACAddress,

    [Parameter(Mandatory=$true)]
    [ValidateScript( { $_ -match [System.Net.IPAddress]$_ } ) ]
    [String]$IPAddress,

    [Parameter()]
    [uint32]$Port=9

)

    ### We need to construct a "Magic Packet".  We need to convert each hex value of the MAC address to its corresponding Byte value. 
    ### The "Magic Packet" is just an array of Byte values.  The first 6 byte values are 255, followed by the byte values of the MAC 
    ### address repeated 16 more times.

    ### Casting to [System.Net.IPAddress] for UdpClient.Connect Method
    $ip = [System.Net.IPAddress]$IPAddress

    ### Generate the MAC address byte values
    $byteArray = $MACAddress -split "[:-]" | ForEach-Object { [Byte] "0x$_" }

    ### Build the "Magic Packet"
    [Byte[]] $magicPacket = (,0xFF * 6) + ($byteArray * 16)

    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.Connect($ip,$Port)  # Port 9 is the default UDP port for WOL traffic
    $udpResult = $udpClient.Send($magicPacket, $magicPacket.Length)
    $udpClient.Close()

}
