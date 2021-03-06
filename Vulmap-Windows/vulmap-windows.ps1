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
    Remark: not supported on PowerShell core (pwsh.exe).

    .EXAMPLE
    PS> Invoke-Vulmap

    Default mode. Conducts a vulnerability scanning.

    .EXAMPLE
    PS> Invoke-Vulmap -Verbose

    Default mode, with verbose messages. Conducts a vulnerability scanning and displays details about progress.

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

    [CmdletBinding()]
    Param(
        [ValidateSet('Default', 'CollectInventory')]
        [string] $Mode = 'Default',
        [switch] $OnlyExploitableVulns,
        [string] $DownloadExploit,
        [switch] $DownloadAllExploits,
        [switch] $SaveInventoryFile,
        [switch] $ReadInventoryFile,
        [string] $InventoryOutFile = 'inventory.json',
        [string] $InventoryInFile = 'inventory.json',
        [string] $Proxy
    )

    $ErrorActionPreference = 'Stop'
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
            Write-Verbose "Loading code to circumvent proxy ssl errors."
            Add-Type -TypeDefinition $TrustAllCertsPolicyCode
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    function Get-ProductList () {
        Write-Verbose "Reading installed software from registry."
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

    function Get-Exploit ($ExploitID) {
        Write-Verbose "Downloading exploit '$ExploitID'."
        $webRequestSplat = @{
            Uri       = $exploitDownloadUri + $ExploitID
            UserAgent = $userAgentString
        }

        if ($Proxy) {
            $webRequestSplat.Proxy = $Proxy
        }

        $request = Invoke-WebRequest @webRequestSplat

        $fileName = ($request.Headers.'Content-Disposition' -split '=')[1].Substring(1)
        $null = New-Item -Path $fileName -ItemType File -Value $request -Force

        Write-Verbose "Saved exploit '$ExploitID' to file '$fileName'."
    }

    function Get-JsonRequestBatches ($inventory) {
        $numberOfBatches = [math]::Ceiling(@($inventory).count / 100)

        for ($i = 0; $i -lt $numberOfBatches; $i++) {
            Write-Verbose "Submitting software to vulmon.com api, batch '$i' of '$numberOfBatches'."
            $productList = $inventory |
                Select-Object -First 100 |
                ForEach-Object {
                    [pscustomobject]@{
                        product = $_.DisplayName
                        version = if ($_.DisplayVersion) { $_.DisplayVersion } else { '' }
                    }
                }

            $inventory = $inventory | Select-Object -Skip 100

            $json_request_data = [ordered]@{
                os           = (Get-CimInstance Win32_OperatingSystem -Verbose:$false).Caption
                product_list = @($productList)
            } | ConvertTo-Json

            $webRequestSplat = @{
                Uri    = $vulMapScannerUri
                Method = 'POST'
                Body   = @{ querydata = $json_request_data }
            }

            if ($Proxy) {
                $webRequestSplat.Proxy = $Proxy
            }

            (Invoke-WebRequest @webRequestSplat).Content | ConvertFrom-Json
        }
    }

    function Resolve-RequestResponses ($responses) {
        $count=0
        foreach ($response in $responses) {
            foreach ($vuln in ($response | Select-Object -ExpandProperty results -ErrorAction SilentlyContinue)) {
                Write-Verbose "Parsing results from vulmon.com api."
                $interests = $vuln |
                    Select-Object -Property query_string -ExpandProperty vulnerabilities |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Product                = $_.query_string
                            'CVE ID'               = $_.cveid
                            'Risk Score'           = $_.cvssv2_basescore
                            'Vulnerability Detail' = $_.url
                            ExploitID              = if ($null -ne $_.exploits) { 'EDB' + ($_.exploits[0].url).Split('{=}')[2] } else { $null }
                            'Exploit Title'        = if ($null -ne $_.exploits) { $_.exploits[0].title } else { $null }
                        }
                    }

                if ($OnlyExploitableVulns -Or $DownloadAllExploits) {
                    $interests = $interests | Where-Object { $null -ne $_.exploits }
                }

                $count += $interests.Count
                Write-Verbose "Found '$count' vulnerabilities so far."

                $interests
            }
        }
    }

    function Invoke-VulnerabilityScan ($inventory_json) {
        Write-Host 'Vulnerability scanning started...'
        $inventory = ConvertFrom-Json $inventory_json

        $responses = Get-JsonRequestBatches $inventory

        $vulmon_api_status_message = $responses[-1] | Select-Object -ExpandProperty message

        $vuln_list = Resolve-RequestResponses $responses

        if ($DownloadAllExploits) {
            foreach ($exp in $vuln_list) {
                $exploit_id = $exp.ExploitID
                Get-Exploit $exploit_id
            }
        }

        Write-Host "Checked $(@($inventory).count) items" -ForegroundColor Green

        if ($null -like $vuln_list) {
            Write-Host "Vulmon.com Api returned message: $vulmon_api_status_message" -ForegroundColor DarkCyan
        }
        else {
            Write-Host "$($vuln_list.Count) vulnerabilities found!" -ForegroundColor Red
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

    function Get-Banner {
        Write-Host "|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
        Write-Host "                                                               	   "
        Write-Host "  ██╗        ██╗   ██╗██╗   ██╗██╗     ███╗   ███╗ █████╗ ██████╗  "
        Write-Host "  ╚██╗       ██║   ██║██║   ██║██║     ████╗ ████║██╔══██╗██╔══██╗ "
        Write-Host "   ╚██╗      ██║   ██║██║   ██║██║     ██╔████╔██║███████║██████╔╝ "
        Write-Host "   ██╔╝      ╚██╗ ██╔╝██║   ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝  "
        Write-Host "  ██╔╝███████╗╚████╔╝ ╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║      "
        Write-Host "  ╚═╝ ╚══════╝ ╚═══╝   ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝      "
        Write-Host "==================================================================="
        Write-Host "\                       Vulmon Mapper v2.2                        /"
        Write-Host " \                        www.vulmon.com                         / "
        Write-Host "  \=============================================================/`n"
    }

    <#-----------------------------------------------------------[Execution]------------------------------------------------------------#>
    Get-Banner
    Write-Host 'Vulmap started...'

    if ($DownloadExploit) {
        Write-Host 'Downloading exploit...'
        Get-Exploit $DownloadExploit
    }
    else {
        $inventory_json = Get-Inventory

        if (! $inventory_json) {
            Write-Warning 'No installed software detected.'
            break
        }

        if ($SaveInventoryFile -Or ($Mode -eq 'CollectInventory')) {
            Write-Host "Saving software inventory to $InventoryOutFile..."
            $inventory_json | Out-File -Encoding UTF8 -FilePath $InventoryOutFile
        }

        if ($Mode -eq 'Default') {
            Invoke-VulnerabilityScan $inventory_json | Out-Default # Out-Default forces PowerShell to ouput this object before 'Done.', as intended.
        }
    }

    Write-Host 'Done.'
}

Invoke-Vulmap
