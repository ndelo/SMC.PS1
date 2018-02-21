param (
    [Parameter(Mandatory=$true)]
    [string]
    $source,

    [Parameter(Mandatory=$true)]
    [string]
    $destination,

    [Parameter(Mandatory=$true)]
    [string]
    $protocol,

    [Parameter(Mandatory=$true)]
    [string]
    $key,

    [Parameter(Mandatory=$true)]
    [string]
    $smc,

    [Parameter(Mandatory=$true)]
    [string]
    $fwcluster
)

# ignore self-signed certificate
 Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
"@
 
 [ServerCertificateValidationCallback]::Ignore();
function query_by_name([string]$name,[string]$type = 'host') {
    
    if ($type -eq 'host') 
    { 
        $name = $name.split('.')[0]
    }

    $response = Invoke-WebRequest -uri $smc_base/elements/$type -Method GET -ContentType "application/json" -WebSession $smc_session

    $results = ($response | ConvertFrom-JSON).result

    foreach ($result in $results) {

        if ($name -eq $result.name)
        {
            $element = $result
        } 
    }

    return $element
}


function query_by_href([string]$href){
    
    $response = Invoke-WebRequest -uri $href -Method Get -ContentType "application/json" -WebSession $smc_session

    return $response.Content | ConvertFrom-Json

}

function add_host([string]$name){

    $ip_address = (Resolve-DnsName $name -DnsOnly A -ErrorAction Stop)[0].ipAddress 
        
    $name = $name.split('.')[0]

    $json = @{'name' = $name; 'address' = $ip_address } | ConvertTo-Json

    $response = Invoke-WebRequest -uri $smc_base/elements/host -Method POST -ContentType "application/json" -Body $json -WebSession $smc_session
    
    return query_by_name($name)
}

function add_to_group([string]$group,[Object]$d_host){

    
    $json = query_by_href((query_by_name $group 'group').href)

    [array]$elements = $json.element
    $elements += $d_host.href
    $json.element = $elements

    $href = $json.link[0].href

    $response = Invoke-WebRequest -uri $href -Method GET -ContentType 'application/json' -WebSession $smc_session

    $headers = @{'etag' = $response.Headers.ETag.trim('"')}
    
    $json = $json | ConvertTo-JSON

    $response = Invoke-WebRequest -uri $href -Method PUT -ContentType 'application/json' -Headers $headers -Body $json -WebSession $smc_session 

    if ($response.StatusCode -ne 200)
    {
        throw "ERROR"
    }
        
}


#### MAIN ####

try 
{
    $base_uri    = "https://$smc:8082/6.2"
    
    # log into api
    $login = @{ 'authenticationkey'= $key }
    $json = $login | ConvertTo-Json

    $login = Invoke-webrequest -uri $base_uri/login -Method POST -Body $json -ContentType "application/json" -SessionVariable smc_session

    if ($login.StatusCode -ne 200)
    {
        throw "There was a problem logging into the SMA SPI"
    }
    

    # lookup destination host, if it does not exist, create it
    $d_host = query_by_name($destination)

    # create destination
    if ($d_host -eq $null) 
    { 
        $d_host = add_host($destination) 
    }

    # lookup source host, if it does not exists, create it
    $s_host = query_by_name($source)

    # create source
    if ($s_host -eq $null)
    {
        $s_host = add_host($source)
        $bastion_access_group = $null
    }
    else
    {
        # check if the host definition has a 'comment' section
        # and if that comment indicates the host is a bastion host
        $s_host_info = query_by_href($s_host.href)

        if ($s_host_info.comment -ne $null) 
        {
            if ($s_host_info.comment.toLower().contains('bastion'))
            {
                # bastion group name
                $bastion_access_group = $s_host_info.comment.split(':')[1].trim() + '-' + $protocol.toUpper() + '-Access'
            }
        }
    }

    if ($bastion_access_group -ne $null)
    {
        add_to_group $bastion_access_group $d_host
    }
    else
    {
        # get ipv4 policy href
        $href = (query_by_name ($protocol.toUpper() + "-Access-Policy") 'sub_ipv4_fw_policy').href
        
        # create template for new rule
        $ipv4_access_rule = @{'action'=@{'action'='allow'};'destinations'=@{'dst'= @()};'comment'='';'services'=@{'service'=@()};'sources'=@{'src'=@()}}

        # get existing ipv4 access rules for subpolicy
        $response = Invoke-WebRequest -uri $href/fw_ipv4_access_rule -Method Get -ContentType 'application/json' -WebSession $smc_session
        $rules = ($response.Content | COnvertFrom-JSON).result

        # find last access rule so we can add our new rule before it. presumably, the last rule is a REJECT all
        if ($rules.count -gt 0) 
        {
            $last_rule_number = ($last_rule = $rules[$rules.count - 1]).name.trim('Rule @')
            $uri = "$href/fw_ipv4_access_rule?before=$last_rule_number"
        }
        else
        {
            $uri = "$href/fw_ipv4_access_rule"
        }

        # add source and destination to our new rule
        $ipv4_access_rule.sources.src = @($s_host.href)
        $ipv4_access_rule.destinations.dst = @($d_host.href)

        # add service 
        if ($protocol.toLower() -eq 'rdp')
        {
            $ipv4_access_rule.services.service = @((query_by_name 'Remote Desktop' 'tcp_service').href)
        }
        elseif ($protocol.toLower() -eq 'ssh')
        {
            $ipv4_access_rule.services.service = @((query_by_name 'SSH' 'tcp_service').href)
        }

         # add comment
         $ipv4_access_rule.comment = "Added by API during build of $source at " + (get-date)

         $json = $ipv4_access_rule | ConvertTo-JSON

         # upload rule
         $response = Invoke-WebRequest -uri $uri -Method Post -ContentType 'application/json' -Body $json -WebSession $smc_session
         
        if ($response.StatusCode -ne '201')
        {
            throw 'Problem creating new rule in SMC.'
        }

         # upload policy to firewall cluster
        $href = (query_by_name $fwcluster 'fw_cluster').href

        $response = Invoke-WebRequest $href/upload -Method Post -ContentType 'application/json' -WebSession $smc_session

        if ($response.StatusCode -eq 202)
        {
            $follower = ($response.content | ConvertFrom-JSON).follower
        }
        else
        {
            throw 'Problem uploading new policy in SMC'
        }

        # query policy upload status until its progress has finished         
        $in_progress = 'True'
        $counter = 0
         
        while ($in_progress -eq 'True')
        {   
            start-sleep -Seconds 3

            $response = Invoke-WebRequest -uri $follower -Method Get -ContentType 'application/json' -WebSession $smc_session
            
            if (($response.StatusCode -ne 200) -or ($counter -gt 100))
            {
                throw 'Problem querying policy status in SMC.'
            }
            else
            {        
                $in_progress = ($response.Content | ConvertFrom-Json).in_progress
            }
               
            $counter ++
        }
    }

    # logout
    $logout = Invoke-WebRequest -Uri $base_uri/logout -Method PUT -WebSession $smc_session
}
catch
{
    return @{'error' = $Error[0].Exception}
}
