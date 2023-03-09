Function Get-zonesByAccountId {
    [cmdletbinding()]
    Param (
        [string]$filepath,
        [string]$xAuthKey,
        [string]$xAuthName
    )

    $filelocation = ""	
    if (!(Test-Path $filepath)) { 
        Write-Error "Invalid file. Exiting..." 
    }
    else {
        $fitem = Get-ChildItem $filepath
        
        #Get file path into a var for to use to save account csv 
        $filelocation = $fitem.FullName.Replace($fitem.Name, "")

        $GetFirewallRulesByZoneId_ScriptFile = $fitem.FullName.Replace($fitem.Name, "GetFirewallRulesByZoneId.ps1")

        #load GetAccessRulesByZoneId.ps1
        . $GetFirewallRulesByZoneId_ScriptFile
             
    }

    #variables
    $X_Auth_Key = $xAuthKey
    $X_Auth_Email = $xAuthName

    $Final_Total_results = @()
    

    $importFileContent = @()
    
    Import-Csv -Path $filepath | ForEach-Object {
        $imprtRecord = @{
            AccountId   = $_.accountid
            AccountName = $_.accountname
        }
            
        $importFileContent += New-Object PSObject -Property $imprtRecord 
    }

    
    foreach ($obj in $importFileContent) {
    
        Write-Host "For Account: " $obj.AccountName
        #$obj.AccountId + ":" + $obj.AccountName
        
        $account_id = $obj.AccountId
        $account_name = $obj.AccountName


        $total_zone_pages = 0
        $zoneUrl = "https://api.cloudflare.com/client/v4/zones?status=active&account.id=" + $account_id + "&account.name=" + $account_name + "&page=1&per_page=50"

        $params = @{
            Uri         = $zoneUrl
            Headers     = @{ 'X-Auth-Key' = $X_Auth_Key
                'X-Auth-Email'        = $X_Auth_Email 
            }
            Method      = 'GET'
            ContentType = 'application/json'
        }

        $zone_rslt = Invoke-RestMethod @params

        $total_zone_pages = $zone_rslt.result_info.total_pages

        #Now get Zoned FW Rules
        :pagedZone for ($current_page = 1; $current_page -le $total_zone_pages; $current_page++) {
    
            $paged_zoneUrl = "https://api.cloudflare.com/client/v4/zones?status=active&account.id=" + $account_id + "&account.name=" + $account_name + "&page=" + $current_page + "&per_page=50"

            $zone_page_params = @{
                Uri         = $paged_zoneUrl
                Headers     = @{ 'X-Auth-Key' = $X_Auth_Key
                    'X-Auth-Email'        = $X_Auth_Email 
                }
                Method      = 'GET'
                ContentType = 'application/json'
            }

            $paged_zone_rslt = Invoke-RestMethod @zone_page_params

            foreach ($zone in $paged_zone_rslt.result) {
                write-host "Get Access Rules for Zone: " $zone.name
                $zone_name = $zone.name
                $rtn_obj = Get-FirewallRulesByZoneId -zone_id $zone.id -acct_id $account_id -acct_name $account_name -xAuthKey $xAuthKey -xAuthName $xAuthName


                $zonefw_filepath = "$filelocation$zone_name.csv"

                #Now save zone fw rules into a csv with zone-name as the file name
                $rtn_obj |
                Select-Object "AccountId", "AccountName", "isPaused", "Desc", "Action", "Priority", "FilterExp", "CreatedOn", "ModifiedOn" | export-csv -Path $zonefw_filepath -NoTypeInformation
                
                #$Final_Total_results += $rtn_obj  
                $rtn_obj.clear()
            }

        }

        $zonefilepath = "$filelocation$account_name.csv"
        $Final_Total_results | 
        Select-Object "AccountId", "ScopeName", "AppliesTo", "IpAddress", "Mode", "Notes", "CreatedOn" | export-csv -Path $zonefilepath -NoTypeInformation

        #AccountId, Mode,Notes,IpAddress,AppliesTo,ScopeName,CreatedOn 
        Write-Host "<<< Done getting all fw rules. >>>"

        $Final_Total_results.Clear()
    }
}