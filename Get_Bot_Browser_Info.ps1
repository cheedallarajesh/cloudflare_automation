
#https://api.cloudflare.com/client/v4/zones/$zone_id/bot_management

Function Get-BotManagementByZoneId {
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
            Headers     = @{ 
                'X-Auth-Key'   = $X_Auth_Key
                'X-Auth-Email' = $X_Auth_Email 
            }
            Method      = 'GET'
            ContentType = 'application/json'
        }

        $zone_rslt = Invoke-RestMethod @params

        #$zone_rslt.result_info.total_pages
        $total_zone_pages = $zone_rslt.result_info.total_pages

        #Now get 
        :pagedZone for ($current_page = 1; $current_page -le $total_zone_pages; $current_page++) {
    
            $paged_zoneUrl = "https://api.cloudflare.com/client/v4/zones?status=active&account.id=" + $account_id + "&account.name=" + $account_name + "&page=" + $current_page + "&per_page=50"
            
            $zone_page_params = @{
                Uri = $paged_zoneUrl
                Headers = @{ 
                    'X-Auth-Key' = $X_Auth_Key
                    'X-Auth-Email' = $X_Auth_Email 
                }
                Method      = 'GET'
                ContentType = 'application/json'
            }

            $paged_zone_rslt = Invoke-RestMethod @zone_page_params

            foreach ($zone in $paged_zone_rslt.result) {
                write-host "Get confgiured parameters for Zone: " $zone.name

                #API call for Bot Management
                $paged_zoneUrl = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/bot_management"
        
                $params = @{
                    Uri = $paged_zoneUrl
                    Headers = @{ 
                        'X-Auth-Key' = $X_Auth_Key
                        'X-Auth-Email' = $X_Auth_Email 
                    }
                    Method = 'GET'
                    ContentType = 'application/json'
                }

                $zone_rslt = Invoke-RestMethod @params

                # API call for Browser-Check Rule
                $paged_zoneUrl_BrowserCheck = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/browser_check"
                $params.Uri = $paged_zoneUrl_BrowserCheck
                $browserchk_rslt = Invoke-RestMethod @params

                # API call for IPv6 Compatibility
                $paged_zoneUrl_IPv6 = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/ipv6"
                $params.Uri = $paged_zoneUrl_IPv6
                $ipv6 = Invoke-RestMethod @params
                # End IPv6 Compatibility Check Rule

                # API call for Onion Routing
                $paged_zoneUrl_OnionRouting = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/opportunistic_onion"
                $params.Uri = $paged_zoneUrl_OnionRouting
                $OnionRouting = Invoke-RestMethod @params
                # End Onion Routing Check Rule

                # API call for IP Geolocation
                $paged_zoneUrl_Geolocation = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/ip_geolocation"
                $params.Uri = $paged_zoneUrl_Geolocation
                $Geolocation = Invoke-RestMethod @params
                # End IP Geolocation Check Rule

                # API call for WAF
                $paged_zoneUrl_waf = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/waf"
                $params.Uri = $paged_zoneUrl_waf
                $WebApplicationFirewall = Invoke-RestMethod @params
                # End WAF Check Rule

                # API call for TLS Version
                $paged_zoneUrl_tls = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/min_tls_version"
                $params.Uri = $paged_zoneUrl_tls
                $TLS_Version = Invoke-RestMethod @params
                # End TLS Version Check Rule
    
                # API call for TLS 1.3 Version
                $paged_zoneUrl_tls_1_3 = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/tls_1_3"
                $params.Uri = $paged_zoneUrl_tls_1_3
                $TLS = Invoke-RestMethod @params
                # End TLS 1.3 Version Check Rule

                # API call for IP Reputation - Security Level
                $paged_zoneUrl_security_level = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/security_level"
                $params.Uri = $paged_zoneUrl_security_level
                $SecurityLevel = Invoke-RestMethod @params
                # End IP Reputition - Security Level Check Rule

                # API call for OWASP ModSecurity Core Rule Set
                $paged_zoneUrl_OWASP = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/firewall/waf/packages"
                $params.Uri = $paged_zoneUrl_OWASP
                $OWASP_ModSecurity = Invoke-RestMethod @params

                foreach ($obj1 in $OWASP_ModSecurity.result) { 
                    if ($obj1.name -eq "OWASP ModSecurity Core Rule Set") {
                        $OWASP_Sensitivity = $obj1.sensitivity
                        $OWASP_action_mode = $obj1.action_mode
                    }
                }
                # End OWASP ModSecurity Core Rule SetCheck Rule

                # API call for HSTS - HTTP Strict Transport Security
                $paged_zoneUrl_hsts = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/security_header"
                $params.Uri = $paged_zoneUrl_hsts
                $HSTSecurity = Invoke-RestMethod @params
                [String]$HSTSValue = $HSTSecurity.result.value.strict_transport_security
                $HSTS = $HSTSValue.Replace('@', '').Replace('}', '').Replace('{', '')
                # End HSTS Check Rule
  
                # API call for Ciphers
                $paged_zoneUrl_ciphers = "https://api.cloudflare.com/client/v4/zones/" + $zone.id + "/settings/ciphers"
                $params.Uri = $paged_zoneUrl_ciphers
                $Ciphers = Invoke-RestMethod @params
                $CipherValues = $Ciphers.result.value -join ','
                # End Ciphers Check Rule

                $botMgmtObj = @{
                    Account_Id              = $account_id            
                    Account_Name            = $account_name
                    Zone_Id                 = $zone.id
                    Zone_Name               = $zone.name
                    Bot_Fight_Mode          = $zone_rslt.result.fight_mode
                    Bot_Management          = $zone_rslt.result.enabled
                    Browser_Integrity_Check = $browserchk_rslt.result.value
                    IPv6_Compatibility      = $ipv6.result.value
                    Onion_Routing           = $OnionRouting.result.value
                    IP_Geolocation          = $Geolocation.result.value
                    WAF                     = $WebApplicationFirewall.result.value
                    TLS_Version             = $TLS_Version.result.value
                    TLS_1_3                 = $TLS.result.value
                    IP_Reputation           = $SecurityLevel.result.value
                    HSTS                    = $HSTS
                    Ciphers                 = $CipherValues
                    OWSAP                   = $OWASP_Sensitivity + ',' + $OWASP_action_mode
                }

                $Final_Total_results += New-Object PSObject -Property $botMgmtObj  
            }

        }

        $zonefilepath = "$filelocation$account_name" + "_" + "$(get-date -Format yyyyMMdd_hhmmss).csv"

        $Final_Total_results | 
        Select-Object "Account_Name", "Zone_Name", "IP_Reputation", "Bot_Fight_Mode", "Bot_Management", "Browser_Integrity_Check", "WAF", "HSTS", "OWSAP", "Ciphers", "TLS_Version", "TLS_1_3", "IPv6_Compatibility", "Onion_Routing", "IP_Geolocation" | export-csv -Path $zonefilepath -NoTypeInformation

        #AccountId, Mode,Notes,IpAddress,AppliesTo,ScopeName,CreatedOn 
        Write-Host "<<< Done getting Zone rules. >>>"

        $Final_Total_results.Clear()
    }

}