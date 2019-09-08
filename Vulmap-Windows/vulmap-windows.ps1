function Invoke-Vulmap {
    <#
.SYNOPSIS
Online Local vulnerability Scanner

.DESCRIPTION
Gets installed software information from the local host and asks to vulmon.com if vulnerabilities and exploits exists. 

.PARAMETER Mode
Mode. Conducts a vulnerability scanning[Default] or [CollectInventory]

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

    Param (
        [string] $Mode = "default",
        [switch] $OnlyExploitableVulns,
        [string] $DownloadExploit = "",
        [switch] $DownloadAllExploits,
        [switch] $SaveInventoryFile,
        [switch] $ReadInventoryFile,
        [string] $InventoryOutFile = "inventory.json",
        [string] $InventoryInFile = "inventory.json",
        [string] $Proxy,
        [switch] $Help
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
    function Send-Request($ProductList) {
        $product_list = '"product_list": ' + $ProductList;
        
        $json_request_data = '{';
        $json_request_data = $json_request_data + '"os": "' + (Get-CimInstance Win32_OperatingSystem).Caption + '",';
        $json_request_data = $json_request_data + $product_list;
        $json_request_data = $json_request_data + '}';

        $postParams = @{querydata = $json_request_data };

        if (![string]::IsNullOrEmpty($Proxy))
        {
            return (Invoke-WebRequest -Uri https://vulmon.com/scannerapi_vv211 -Method POST -Body $postParams -Proxy $Proxy).Content;
        }
        else {
            return (Invoke-WebRequest -Uri https://vulmon.com/scannerapi_vv211 -Method POST -Body $postParams).Content;
        }
    }
    function Get-ProductList() {
        $registry_paths = ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
   
        $objectArray = @();
    
        foreach ($registry_path in $registry_paths) {
            
            if ([bool](Get-ChildItem -Path $registry_path -ErrorAction SilentlyContinue)) {
            
                $subkeys = Get-ChildItem -Path $registry_path;
    
                ForEach ($key in $subkeys) {
                    $DisplayName = $key.getValue('DisplayName');
    
                    if (!([string]::IsNullOrEmpty($DisplayName))) {
                        $DisplayVersion = $key.GetValue('DisplayVersion');
    
                        $Object = [pscustomobject]@{ 
                            DisplayName     = $DisplayName.Trim();
                            DisplayVersion  = $DisplayVersion;
                            NameVersionPair = $DisplayName.Trim() + $DisplayVersion;
                        };
    
                        $Object.pstypenames.insert(0, 'System.Software.Inventory');
    
                        $objectArray += $Object;
                    }
                }                   
            }               
        }

        $objectArray | sort-object NameVersionPair -unique;
    }   
    function Get-Exploit($ExploitID) {  
	    if (![string]::IsNullOrEmpty($Proxy))
        {
			$request1 = Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -Proxy $Proxy -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0";
			Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -Proxy $Proxy -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0" -OutFile ( ($request1.Headers."Content-Disposition" -split "=")[1].substring(1));
		}
		else
		{
			$request1 = Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0";
			Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0" -OutFile ( ($request1.Headers."Content-Disposition" -split "=")[1].substring(1));
		}
    }
    function Get-Vulmon($product_list) {
        $response = (Send-Request -ProductList $product_list | ConvertFrom-Json);
        $interests = @();
        foreach ($vuln in $response.results) {
            
            if ($OnlyExploitableVulns -Or $DownloadAllExploits) {
                $interests += $vuln | Select-Object -Property query_string -ExpandProperty vulnerabilities | where-object { $_.exploits -ne $null } | `
                    Select-Object -Property @{N = 'Product'; E = { $_.query_string } }, @{N = 'CVE ID'; E = { $_.cveid } }, @{N = 'Risk Score'; E = { $_.cvssv2_basescore } }, @{N = 'Vulnerability Detail'; E = { $_.url } }, @{L = 'ExploitID'; E = { if ($null -ne $_.exploits) { "EDB" + ($_.exploits[0].url).Split("{=}")[2] }else { null } } }, @{L = 'Exploit Title'; E = { if ($null -ne $_.exploits) { $_.exploits[0].title }else { null } } };

                if ($DownloadAllExploits) {    
                    foreach ($exp in $interests) {
                        $exploit_id = $exp.ExploitID;
                        Get-Exploit($exploit_id);                     
                    }
                }
            }
            else {
                $interests += $vuln | Select-Object -Property query_string -ExpandProperty vulnerabilities | `
                    Select-Object -Property @{N = 'Product'; E = { $_.query_string } }, @{N = 'CVE ID'; E = { $_.cveid } }, @{N = 'Risk Score'; E = { $_.cvssv2_basescore } }, @{N = 'Vulnerability Detail'; E = { $_.url } }, @{L = 'Exploit ID'; E = { if ($null -ne $_.exploits) { "EDB" + ($_.exploits[0].url).Split("{=}")[2] }else { null } } }, @{L = 'Exploit Title'; E = { if ($null -ne $_.exploits) { $_.exploits[0].title }else { null } } };
            }
        }
        return $interests;
    }
    function Invoke-VulnerabilityScan() {
        Write-Host 'Vulnerability scanning started...';
        $inventory = ConvertFrom-Json($inventory_json);

        $vuln_list = @();
        $count = 0;
        foreach ($element in $inventory) {
            # Build JSON from inventory
            if ($element.DisplayName) {
                $product_list = $product_list + '{';
                $product_list = $product_list + '"product": "' + $element.DisplayName + '",';
                $product_list = $product_list + '"version": "' + $element.DisplayVersion + '"';
                $product_list = $product_list + '},';
            }
                   
            $count++;
            if (($count % 100) -eq 0) {
                $product_list = $product_list.Substring(0, $product_list.Length - 1);
                $http_param = '[' + $product_list + ']';
                $http_response = Get-Vulmon($http_param);
                $vuln_list += $http_response;
                $product_list = "";
            }
        }
        $product_list = $product_list.Substring(0, $product_list.Length - 1);
        $http_param = '[' + $product_list + ']';
        $http_response = Get-Vulmon($http_param);
        $vuln_list += $http_response;
        Write-Host "Checked $count items";

        if ($vuln_list.Length -eq 0) {
            Write-Host 'No vulnerabilities found';
        } else {
            $vuln_count = $vuln_list.Length;
            Write-Host "$vuln_count vulnerabilities found!";
            $vuln_list | Format-Table -AutoSize;
        }
    }
    function Get-Inventory{
        if ($ReadInventoryFile) {
            # read from file
            Write-Host "Reading software inventory from $InventoryInFile...";
            $inventory_json = Get-Content -Encoding UTF8 -Path $InventoryInFile | Out-String;
        } else {
            Write-Host "Collecting software inventory...";
            $inventory = Get-ProductList;
            $inventory_json = ConvertTo-JSON $inventory;
        }
        Write-Host 'Software inventory collected';
        return $inventory_json;

    }
    <#-----------------------------------------------------------[Execution]------------------------------------------------------------#>
    Write-Host 'Vulmap started...';
    if (!([string]::IsNullOrEmpty($DownloadExploit))) {
        "Downloading exploit...";
        Get-Exploit($DownloadExploit);
    }
    else {
        $inventory_json = Get-Inventory;
        # Save Inventory to File
        if (($SaveInventoryFile) -Or ($Mode -eq "CollectInventory")) {
            Write-Host "Saving software inventory to $InventoryOutFile... ";
            $inventory_json | Out-File -Encoding UTF8 -FilePath $InventoryOutFile;
            }

        if (!($Mode -eq "CollectInventory")){
           # Mode 'Default'
           invoke-VulnerabilityScan;
         }
    }
    Write-Host 'Done.';
}

Invoke-Vulmap;
