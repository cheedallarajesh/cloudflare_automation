Function Get-FirewallRulesByZoneId {
    [cmdletbinding()]
    Param (
        [string]$zone_id,
        [string]$acct_id,
        [string]$acct_name,
        [string]$xAuthKey,
        [string]$xAuthName
    )

    $X_Auth_Key = $xAuthKey
    $X_Auth_Email = $xAuthName

    $total_pages = 0

    $fwRules = "https://api.cloudflare.com/client/v4/zones/" + $zone_id + "/firewall/rules?page=1&per_page=100"

    $params = @{
        Uri         = $fwRules
        Headers     = @{ 'X-Auth-Key' = $X_Auth_Key
            'X-Auth-Email'        = $X_Auth_Email 
        }
        Method      = 'GET'
        ContentType = 'application/json'
    }

    Write-Host "Executing API call to get total pages...."
    $page_rslt = Invoke-RestMethod @params

    $total_pages = $page_rslt.result_info.total_pages
    Write-Host "Total pages: " + $total_pages

    $Total_results = @()

    :paged for ($current_page = 1; $current_page -le $total_pages; $current_page++) {

        $fwRulesByPage = "https://api.cloudflare.com/client/v4/zones/" + $zone_id + "/firewall/rules?page=" + $current_page + "&per_page=100"

        $params = @{
            Uri         = $fwRulesByPage
            Headers     = @{ 'X-Auth-Key' = $X_Auth_Key
                'X-Auth-Email'        = $X_Auth_Email 
            }
            Method      = 'GET'
            ContentType = 'application/json'
        }

        $rslt = Invoke-RestMethod @params
    
        foreach ($itm in $rslt.result) {
            $fwRecord = @{
                AccountId   = $acct_id
                AccountName = $acct_name            
                isPaused    = $itm.paused              
                Desc        = $itm.description
                Action      = $itm.action
                Priority    = $itm.priority
                FilterExp   = $itm.filter.expression
                CreatedOn   = $itm.created_on
                ModifiedOn  = $itm.modified_on
            }

            $Total_results += New-Object PSObject -Property $fwRecord                
        }
    }
    return $Total_results
}