function Invoke-Vulmap {
    <#
    .SYNOPSIS
    Online Local vulnerability Scanner

    .DESCRIPTION
    Gets installed software information from the local host and asks to vulmon.com if vulnerabilities and exploits exists.

    .PARAMETER Mode
    Mode. Conducts a vulnerability scanning [Default] or [CollectInventory]

    .PARAMETER OnlyExploitableVulns
    Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.

    .PARAMETER DownloadExploit
    Downloads given exploit.

    .PARAMETER DownloadAllExploits
    Scans the computer and downloads all available exploits.

    .PARAMETER ReadInventoryFile
    Uses software inventory file rather than scanning local computer.

    .PARAMETER SaveInventoryFile
    Saves software inventory file. Enabled automatically when Mode is 'CollectInventory'.

    .PARAMETER InventoryInFile
    Input JSON file name referred by SaveInventoryFile. Default is 'inventory.json'.

    .PARAMETER InventoryOutFile
    Output JSON file name referred by ReadInventoryFile. Default is 'inventory.json'.

    .PARAMETER Proxy
    Specifies an HTTP proxy server. Enter the URI of a network proxy server. (-Proxy http://localhost:8080)

    .EXAMPLE
    PS> Invoke-Vulmap

    Default mode. Conducts a vulnerability scanning.

    .EXAMPLE
    PS> Invoke-Vulmap -OnlyExploitableVulns

    Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.

    .EXAMPLE
    PS> Invoke-Vulmap -DownloadExploit EDB9386

    Downloads given exploit.

    .EXAMPLE
    PS> Invoke-Vulmap -DownloadAllExploits

    Scans the computer and downloads all available exploits.

    .EXAMPLE
    PS> Invoke-Vulmap -Mode CollectInventory

    Collects software inventory but does not conduct a vulnerability scanning.
    Software inventory will be saved as 'inventory.json' in default.

    .EXAMPLE
    PS> Invoke-Vulmap -Mode CollectInventory -InventoryOutFile pc0001.json

    Collects software inventory and save it with given file name.
    Does not conduct a vulnerability scanning.

    .EXAMPLE
    PS> Invoke-Vulmap -SaveInventoryFile

    Conducts a vulnerability scanning and saves software inventory to inventory.json file.

    .EXAMPLE
    PS> Invoke-Vulmap -SaveInventoryFile -InventoryOutFile pc0001.json

    Conducts a vulnerability scanning and saves software inventory to given file name.

    .EXAMPLE
    PS> Invoke-Vulmap -ReadInventoryFile

    Conducts a vulnerability scanning based on software inventory from file.
    Software inventory will be loaded from 'inventory.json' in default.

    .EXAMPLE
    PS> Invoke-Vulmap -ReadInventoryFile -InventoryInFile pc0001.json

    Conducts a vulnerability scanning based on software inventory file loaded from given file name.

    .EXAMPLE
    PS> Invoke-Vulmap -Proxy http://127.0.0.1:8080

    Conducts a vulnerability scanning through an HTTP proxy server.

    .LINK
    https://github.com/vulmon
    https://vulmon.com
    #>

    Param(
        [Parameter()]
        [ValidateSet('Default', 'CollectInventory')]
        [string] $Mode = 'Default',

        [switch] $OnlyExploitableVulns,
        [string] $DownloadExploit,
        [switch] $DownloadAllExploits = $true,
        [switch] $SaveInventoryFile,
        [switch] $ReadInventoryFile,
        [string] $InventoryOutFile = 'inventory.json',
        [string] $InventoryInFile = 'inventory.json',
        [string] $Proxy
    )

    $ErrorActionPreference = 'Stop'
    $global:vulmon_api_status_message = ''
    $registry_paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    $vulMapScannerUri = 'https://vulmon.com/scannerapi_vv211'
    $exploitDownloadUri = 'https://vulmon.com/downloadexploit?qid='
    $userAgentString = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0'

    $TrustAllCertsPolicyCode = @'
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
                }
        }
'@

    if ($Proxy) {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            Write-Error -Message 'Proxy support is not available for PowerShell Core, please use Windows PowerShell (powershell.exe) instead of PowerShell Core (pwsh.exe) if you need to use a proxy.'
        }
        else {
            # Ignores ssl-errors which is required for proxies:
            Add-Type -TypeDefinition $TrustAllCertsPolicyCode
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    function Send-Request($ProductList) {
        $product_list = '"product_list": ' + $ProductList

        $json_request_data = '{'
        $json_request_data = $json_request_data + '"os": "' + (Get-CimInstance Win32_OperatingSystem).Caption + '",'
        $json_request_data = $json_request_data + $product_list
        $json_request_data = $json_request_data + '}'

        $webRequestSplat = @{
            Uri    = $vulMapScannerUri
            Method = 'POST'
            Body   = @{querydata = $json_request_data }
        }

        if ($Proxy) {
            $webRequestSplat.Proxy = $Proxy
        }

        return (Invoke-WebRequest @webRequestSplat).Content
    }

    function Get-ProductList() {
        @(
            foreach ($registry_path in $registry_paths) {
                $subkeys = Get-ChildItem -Path $registry_path -ErrorAction SilentlyContinue

                if ($subkeys) {
                    ForEach ($key in $subkeys) {
                        $DisplayName = $key.getValue('DisplayName')

                        if ($null -notlike $DisplayName) {
                            $DisplayVersion = $key.GetValue('DisplayVersion')

                            [PSCustomObject]@{
                                PSTypeName      = 'System.Software.Inventory'
                                DisplayName     = $DisplayName.Trim()
                                DisplayVersion  = $DisplayVersion
                                NameVersionPair = $DisplayName.Trim() + $DisplayVersion
                            }
                        }
                    }
                }
            }
        ) | Sort-Object NameVersionPair -Unique
    }

    function Get-Exploit($ExploitID) {
        $webRequestSplat = @{
            Uri       = $exploitDownloadUri + $ExploitID
            UserAgent = $userAgentString
        }

        if ($Proxy) {
            $webRequestSplat.Proxy = $Proxy
        }

        $request = Invoke-WebRequest @webRequestSplat
        $request | Out-File -Path ($request.Headers.'Content-Disposition' -split '=')[1].Substring(1)
    }

    function Get-Vulmon($product_list) {
        $response = (Send-Request -ProductList $product_list | ConvertFrom-Json)

        $status_message = ($response | Select-Object message)
        $global:vulmon_api_status_message = $status_message

        $interests = $(
            foreach ($vuln in $response.results) {
                $tmp = $vuln |
                    Select-Object -Property query_string -ExpandProperty vulnerabilities |
                    ForEach-Object {
                        [pscustomobject]@{
                            Product                = $_.query_string
                            'CVE ID'               = $_.cveid
                            'Risk Score'           = $_.cvssv2_basescore
                            'Vulnerability Detail' = $_.url
                            ExploitID              = if ($null -ne $_.exploits) { 'EDB' + ($_.exploits[0].url).Split('{=}')[2] } else { $null }
                            'Exploit Title'        = if ($null -ne $_.exploits) { $_.exploits[0].title } else { $null }
                        }
                    }

                if ($OnlyExploitableVulns -Or $DownloadAllExploits) {
                    $tmp = $tmp | Where-Object { $null -ne $_.exploits }
                }

                $tmp
            }
        )

        if ($DownloadAllExploits) {
            foreach ($exp in $interests) {
                $exploit_id = $exp.ExploitID
                Get-Exploit($exploit_id)
            }
        }

        return $interests
    }

    function Invoke-VulnerabilityScan() {
        Write-Host 'Vulnerability scanning started...'
        $inventory = ConvertFrom-Json $inventory_json

        $vuln_list = @()
        $count = 0
        foreach ($element in $inventory) {
            # Build JSON from inventory
            if ($element.DisplayName) {
                $product_list = $product_list + '{'
                $product_list = $product_list + '"product": "' + $element.DisplayName + '",'
                $product_list = $product_list + '"version": "' + $element.DisplayVersion + '"'
                $product_list = $product_list + '},'
            }

            $count++;
            if (($count % 100) -eq 0) {
                $product_list = $product_list.Substring(0, $product_list.Length - 1)
                $http_param = '[' + $product_list + ']'
                $http_response = Get-Vulmon $http_param 
                $vuln_list += $http_response
                $product_list = ''
            }
        }
        $product_list = $product_list.Substring(0, $product_list.Length - 1)
        $http_param = '[' + $product_list + ']'
        $http_response = Get-Vulmon $http_param
        $vuln_list += $http_response
        Write-Host "Checked $count items"

        if ($vuln_list.Length -eq 0) {
            Write-Output $global:vulmon_api_status_message
        }
        else {
            $vuln_count = $vuln_list.Length
            Write-Host "$vuln_count vulnerabilities found!"
            $vuln_list | Format-Table -AutoSize
        }
    }

    function Get-Inventory {
        if ($ReadInventoryFile) {
            # read from file
            Write-Host "Reading software inventory from $InventoryInFile..."
            $inventory_json = Get-Content -Encoding UTF8 -Path $InventoryInFile | Out-String
        }
        else {
            Write-Host 'Collecting software inventory...'
            $inventory = Get-ProductList
            $inventory_json = ConvertTo-Json $inventory
        }

        Write-Host 'Software inventory collected'
        return $inventory_json
    }

    <#-----------------------------------------------------------[Execution]------------------------------------------------------------#>
    Write-Host 'Vulmap started...'

    if ($DownloadExploit) {
        Write-Host 'Downloading exploit...'
        Get-Exploit $DownloadExploit
    }
    else {
        $inventory_json = Get-Inventory

        if ($SaveInventoryFile -Or ($Mode -eq 'CollectInventory')) {
            Write-Host "Saving software inventory to $InventoryOutFile..."
            $inventory_json | Out-File -Encoding UTF8 -FilePath $InventoryOutFile
        }

        if ($Mode -eq 'Default') {
            Invoke-VulnerabilityScan | Out-Default # Out-Default forces PowerShell to ouput this object before 'Done.', as intended.
        }
    }

    Write-Host 'Done.'
}

Invoke-Vulmap
