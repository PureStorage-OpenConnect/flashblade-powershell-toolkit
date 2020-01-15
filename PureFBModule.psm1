<#
	===========================================================================
	Created by:   	aj@purestorage.com
	Organization: 	Pure Storage, Inc.
	Filename:     	PureFBModule.psd1
	Copyright:	(c) 2020 Pure Storage, Inc.
	Module Name: 	PureDBModule
	Description: 	PowerShell Script Module (.psm1)
	-------------------------------------------------------------------------
	Disclaimer
 	The sample script and documentation are provided AS IS and are not supported by 
	the author or the author’s employer, unless otherwise agreed in writing. You bear 
	all risk relating to the use or performance of the sample script and documentation. 
	The author and the author’s employer disclaim all express or implied warranties 
	(including, without limitation, any warranties of merchantability, title, infringement 
	or fitness for a particular purpose). In no event shall the author, the author’s employer 
	or anyone else involved in the creation, production, or delivery of the scripts be liable 
	for any damages whatsoever arising out of the use or performance of the sample script and 
	documentation (including, without limitation, damages for loss of business profits, 
	business interruption, loss of business information, or other pecuniary loss), even if 
	such person has been advised of the possibility of such damages.
	===========================================================================

Cmdlets:
 Get-Pfb
 Add-Pfb
 Update-Pfb
 Delete-Pfb

 Functions with Internal in the name are not Exported e..g Get-InternalPfbJSON

 Default variables for FlashBlade, APITOKEN, APIVers and SkipCertificateCheck are read from the file controlled by the $JSON_FILE variable below.
 If you want to override these, you can specify -FlashBlade and -APIToken when running a cmdlet. APIVers is defaulted below, but can also be over-ridden if you comment that variable out. 

 To Do:
 FIX  Get-NOPfbLogS
 Update Help and add more examples.
 Testing, more testing.

 Author:
 aj@purestorage.com

----------------------------------------------------------------------------
#>

#Requires -Version 6.0
$AUTH_TOKEN = $null;
$DEBUG = 0;
$APIVers = 1.8;
$JSON_FILE = 'FlashBlade.JSON';
 
function Get-InternalPfbJson() 
{
<#
.SYNOPSIS
	Reads JSON file for config information.
.DESCRIPTION
	Helper function
	This function reads a JSON file to retrieve the API Token, FlashBlade IP Address / FQDN and the API Version.
.OUTPUTS
        FlashBlade IP
        FlashBlade API Token
        FlashBlade API Version
        Confirm Certificate Check
.NOTES
	Internal only.
#>
        $json = Get-Content -Raw ($JSON_FILE) | out-string | ConvertFrom-Json;
        #$json = Get-Content -Raw FlashBlade.JSON | out-string | ConvertFrom-Json;
	$json | ForEach-Object { 
			$FlashBlade = $_.FlashBlade
			$ApiToken = $_.APIToken
                        $ApiVers = $_.APIvers
                        $SkipCertificateCheck = $_.SkipCertificateCheck
		}
	if ($DEBUG) { write-host "Get-InternalPfbJson IP = $FlashBlade " } ; 
	
	return @($FlashBlade,$ApiToken,$ApiVers,$SkipCertificateCheck)
}

function Get-InternalPfbAuthToken() 
{
<#
.SYNOPSIS
	Gets AuthToken from array for authentication
.DESCRIPTION
	Helper function
	This function connects to the FlashBlade and use the API_Token to retrieve an Auth_Token as $Token.	
.OUTPUTS
        FlashBlade Auth Token
.NOTES
	Internal only.
#>
        if ($DEBUG) { write-host "Get-InternalPfbAuthToken IP =  $FlashBlade" } ; 
        
        $Token = $null;
        if ( $null -ne $AUTH_TOKEN ) {
                $Token = $AUTH_TOKEN;
        } else {
                $url = "/api/login";
                $link = "https://$FlashBlade$url";
                $headers = @{"api-token" = "$ApiToken"};
                try {
                        $obj = Invoke-RestMethod -SkipCertificateCheck -Method POST -Headers $headers -Uri $link -RHV 'Headers' 
                        $Token = $Headers.'x-auth-token';
                        if ($DEBUG) { Write-Host "TOKEN: $Token" }
                        return $Token;
                } 
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "

                        If ($_.Exception.Response.StatusCode.value__) {
                                $myMessage = ($_.Exception.Response.StatusCode.value__ ).ToString().Trim();
                                Write-Output $myMessage;
                            }
                         If  ($_.Exception.Message) {
                                $myMessage = ($_.Exception.Message).ToString().Trim();
                                Write-Output $myMessage;
                        }

                        break;
                     }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                    
                        $myMessage = ($_.Exception.Message).ToString().Trim();
                        Write-Output $myMessage;

                        break;
                }
        }
}

function Get-InternalPfbAuthTokenLogout( $Token )
{
<#
.SYNOPSIS
	Terminates Auth Session
.DESCRIPTION
	Helper function
	This function terminates the AUTH Token session and logs out of the array
.NOTES
	Not used for outside call, internal only.
#>
        $url = "/api/logout";
        $link = "https://$FlashBlade$url";
        $headers = @{"x-auth-token" = "$Token"};

        try { 
                $obj = Invoke-RestMethod -SkipCertificateCheck -Method POST -Headers $headers -Uri $link -RHV 'Headers'
        }
        catch 	{ 
                return $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand errors
        }

}

function Get-InternalHTTPError ()
{
        If ($_.Exception.Response.StatusCode.value__) {
                $myMessage = ($_.Exception.Response.StatusCode.value__ ).ToString().Trim();
                Write-Output $myMessage;
                }
                If  ($_.Exception.Message) {
                        $myMessage = ($_.Exception.Message).ToString().Trim();
                        Write-Output $myMessage;
                }
                break;
}

function Get_InternalCatchallError () 
{                 
        $myMessage = ($_.Exception.Message).ToString().Trim();
        Write-Output $myMessage;
        break;
}

function Get-PfbAPIVers()
{
<#
.SYNOPSIS
        Lists the supported REST API versions for the FlahBlade  array
.DESCRIPTION
        Helper function	
        This function Lists the supported REST API versions for the FlahBlade  array
.EXAMPLE
        PS> Get-PfbAPIVers
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
.OUTPUTS
        versions 
.NOTES
        Tested
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
        $url = "/api/api_version";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.versions;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }		
}

function Get-PfbAlert()
{
<#
.SYNOPSIS
        Lists Array Alerts
.DESCRIPTION
        Helper function
        This function lists the FlashBlade array Alerts - sorting and filtering is available
        Requires the x-auth-token header returned by the POST login request that created the REST session.
.EXAMPLE
        PS> Get-PfbAlert -Filter 'name=1'
        PS> Get-PfbAlert -Filter 'state="opened"'
        PS> Get-PfbAlert -Sort 'state'
        PS> Get-PfbAlert -Filter "(contains(action,'quota'))"
.INPUTS
        FlashBlade (Not Mandatory)
        ApiToken (Not Mandatory)
        Names (Not Mandatory)
        Ids (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        alerts response       
        name
        index
        flagged
        code
        severity
        component
        state
        created
        updated
        subjet
        description
        Knowledge_base_url
        action
        variables
                @ Array of context specific variables
        id        
.NOTES
        Tested
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/alerts";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {$
                $uri.Add('token' , $Token)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbAlert()
{
<#
.SYNOPSIS
        Modifies/Updates Array Alerts
.DESCRIPTION
        Helper function
        This function modifies FlashBlade array Alerts
.EXAMPLE
        PS> Update-PfbAlert -Names 'name of alert' -Attributes ' {"flagged":"true"} '
.INPUTS
        FlashBlade (Not Mandatory)
        ApiToken (Not Mandatory)
        Names (Not Mandatory)
        Ids (Not Mandatory)
        Attributess (Not Mandatory)
        InputFile (not mandatory)
                        
.OUTPUTS
        alerts response       
        name
        index
        flagged
        code
        severity
        component
        state
        created
        updated
        subjet
        description
        Knowledge_base_url
        action
        variables
                @ Array of context specific variables
        id        
.NOTES
        Tested                      
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
} else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/alerts";                               
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty);
        
        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}
 
function Get-PfbAlertWatcher()
{
<#
.SYNOPSIS
        Returns or tests the Alert Watcher Email Addresses
.DESCRIPTION
        Helper function
        This function returns the Alert Watcher Email Addresses
        This function can also test an email address 

.EXAMPLE
        PS> Get-PfbAlertWatcher        
        PS> Get-PfbAlertWatcher -Names 'a*'
        PS> Get-PfbAlertWatcher -Filter "(contains(name,'par'))"
        
        Test an alert watcher email
        PS> Get-PfbAlertWatcher -Test -Names 'email to test'
        Testing can be used with -Names and -Sort or -Filter

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Test (Not Mandatory)
                        
.OUTPUTS
        alert watchers response       
        name enabled id
.NOTES
        Tested                                      
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Test 

);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
if ($Test) {        
        $url = "/api/$ApiVers/alert-watchers/test";
}  else {
        $url = "/api/$ApiVers/alert-watchers";
}

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbAlertWatcher()
{
<#
.SYNOPSIS
        Adds an Alert Watcher Email Addresses
.DESCRIPTION
        Helper function
        This function Adds an Alert Watcher Email Addresses
.EXAMPLE
        PS> Add-PfbAlertWatcher -Names '<email address>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                        
.OUTPUTS
        alert watcher response       
                
.NOTES
      Tested                                          
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/alert-watchers";                
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbAlertWatcher()
{
<#
.SYNOPSIS
        Update / Modify Array Alert Watcher emails
.DESCRIPTION
        Helper function
        This function modifies Alert Watcher email addresses
.EXAMPLE
        PS> Update-PfbAlertsWatcher -Names '<alert email>' -Enabled 'true'
        PS> Update-PfbAlertsWatcher -Names '<alert email>' -Enabled 'false'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Enabled (Not Mandatory)
                        
.OUTPUTS
        alerts response       
                
.NOTES
       Tested                                         
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Enabled = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}
        
if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/alert-watchers";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        
        $body = @{enabled = $Enabled};

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbAlertWatcher()
{
<#
.SYNOPSIS
        Deletes an Alert Watcher Email Addresses
.DESCRIPTION
        Helper function
        This function Deletes an Alert Watcher Email Addresses
.EXAMPLE
        PS> Remove-PfbAlertWatcher -Names '<email of watcher>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                        
.OUTPUTS
        alert watchers response       
                
.NOTES
        Tested                               
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}
        
if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/alert-watchers";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbArray()
{
<#
.SYNOPSIS
        Lists array attributes
.DESCRIPTION
        Helper function
        This function lists FlashBlade Array configuration information
.EXAMPLE
        PS> Get-PfbArray
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
                        
.OUTPUTS
        Arrays response       
        _as_of
        id
        name
        os
        revision
        version
        ntp_servers
                
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
};

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/arrays";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbArray()
{
<#
.SYNOPSIS
        Modifies attributes of the array
.DESCRIPTION
        Helper function
        This function modifies the arrays NTP Server information
.EXAMPLE
        PS> Update-PfbArray -NTPServers 'xxx.xxx.xxx.xxx,xxx.xxx.xxx.xxx,xxx.xxx.xxx.xxx' -Name '<name of array>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Name (Not Mandatory)
        NTPServers (Mandatory)
                        
.OUTPUTS
        Response       
        name
        ntp_servers        
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Name = $null,
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $NTPServers = $null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/arrays";
        $link = "https://$FlashBlade$url";    
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)    
        
        $body = @{
                'ntp_servers' = @(
                        $NTPServers
                        )
        }
        if ($Name) {
                $body.Add('name', $Name)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbArraySpace()
{
<#
.SYNOPSIS
        Lists available and used space on the array.
.DESCRIPTION
        Helper function
        This function lists FlashBlade Array space information such as compression etc
.EXAMPLE
        PS> Get-PfbArraySpace 
        PS> Get-PfbArraysSpace -Type 'file-system'
        PS> Get-PfbArraySpace -Type 'object-store'
        List the historical space statistics of the array (defaults to every 30 seconds) for a specified range of time
        Get-PfbArraySpace -StartTime 1497398400000 -EndTime 1510684860000 -Resolution 30000
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        end_time (Not Mandatory)
        Resolution (Not Mandatory)
        Start_Time (Not Mandatory)
        Type (Not Mandatory)
                        
.OUTPUTS
        Space response       
        capacity
        name
        space
                data_reduction
                snapshots
                total_physical
                unique
                virtual
        time

.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $EndTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Resolution,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $StartTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Type
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
};

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/arrays/space"; 
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($EndTime) {
                $uri.Add('end_time', $EndTime)
        }
        if ($Resolution) {
                $uri.Add('resolution' , $Resolution)
        }
        if ($StartTime) {
                $uri.Add('start_time' , $StartTime)
        }
        if ($Type) {
                $uri.Add('type' , $Type)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbArrayPerformance()
{
<#
.SYNOPSIS
        Lists Arrays FileSystem Performance
.DESCRIPTION
        Helper function
        This function lists FlashBlade FileSystem Performance Information at a given time period
.EXAMPLE
        PS> Get-PfbArrayPerformance
        PS> Get-PfbArrayPerformance -Protocol 'nfs'
        PS> Get-PfbArrayPerformance -Protocol 'nfs' -Type 'file-system'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        end_time (Not Mandatory)
        Resolution (Not Mandatory)
        start_time (Not Mandatory)
        Protocol (Not Mandatory)
        Type (Not Mandatory)
                        
.OUTPUTS
        Performance response       
        name                
        writes_per_sec      
        reads_per_sec       
        others_per_sec      
        usec_per_write_op   
        usec_per_read_op    
        usec_per_other_op   
        read_bytes_per_sec  
        write_bytes_per_sec 
        time                
        bytes_per_read     
        bytes_per_write     
        bytes_per_op        
        output_per_sec      
        input_per_sec       
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $EndTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Resolution,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $StartTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Protocol = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Type = $null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
};

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/arrays/performance"; 
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($EndTime) {
                $uri.Add('end_time', $EndTime)
        }
        if ($Resolution) {
                $uri.Add('Resolution' , $Resolution)
        }
        if ($StartTime) {
                $uri.Add('start_time' , $StartTime)
        }
        if ($Type) {
                $uri.Add('type' , $Type)
        }
        if ($Protocol) {
                $uri.Add('protocol' , $Protocol)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbArrayClientPerformance()
{
<#
.SYNOPSIS
        Lists Clients Performance Metrics
.DESCRIPTION
        Helper function
        This function lists client performance metrics per protocol for a given time period
.EXAMPLE
        PS> Get-PfbArrayClientPerformance -Names 'xxx.xxx.xxx.xxx'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)

                        
.OUTPUTS
        Clients Performance Response       
        name                
        writes_per_sec      
        reads_per_sec       
        others_per_sec      
        usec_per_write_op   
        usec_per_read_op    
        usec_per_other_op   
        read_bytes_per_sec  
        write_bytes_per_sec 
        time                
        bytes_per_read      
        bytes_per_write     
        bytes_per_op                
.NOTES
        Tested                                       
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
};

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/arrays/clients/performance";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Sort) {$
                $uri.Add('sort' , $Sort)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbArrayHttpSpecificPerformance()
{
<#
.SYNOPSIS
        Lists Array HTTP specific performance metrics
.DESCRIPTION
        Helper function
        This function lists FlashBlade HTTP protocol specfic performance metrics for a given time period
.EXAMPLE
        PS> Get-PfbArrayHttpSpecificPerformance
        List the array's historical HTTP performance metrics with a specific start time and end_time
        PS> Get-PfbArrayHttpSpecificPerformance -start_time '1497398400000' -end_time '1510684860000' -Resolution '30000'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        end_time (Not Mandatory)
        Resolution (Not Mandatory)
        start_time (Not Mandatory)
        Type (Not Mandatory)
                        
.OUTPUTS
        HTTP Performance response       
        name                   
        read_dirs_per_sec      
        write_dirs_per_sec     
        read_files_per_sec     
        write_files_per_sec    
        others_per_sec         
        usec_per_read_dir_op   
        usec_per_write_dir_op  
        usec_per_read_file_op  
        usec_per_write_file_op 
        usec_per_other_op      
        time                   

.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $EndTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Resolution,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $StartTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Type = $null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
};

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/arrays/http-specific-performance";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($EndTime) {
                $uri.Add('end_time' , $EndTime)
        }
        if ($Resolution) {
                $uri.Add('resolution' , $Resolution)
        }
        if ($StartTime) {
                $uri.Add('start_time' , $StartTime)
        }
        if ($Type) {
                $uri.Add('Type' , $Type)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbArrayS3SpecificPerformance()
{
<#
.SYNOPSIS
        Lists S3 Specific Performance Metrics
.DESCRIPTION
        Helper function
        This function lists FlashBlade S3 specific performance metrics for a given time period
.EXAMPLE
        PS> Get-PfbArrayS3SpecicPerformance
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        end_time (Not Mandatory)
        Resolution (Not Mandatory)
        start_time (Not Mandatory)
        Type (Not Mandatory)
                        
.OUTPUTS
        S3 Performance response       
        name                     
        read_buckets_per_sec     
        write_buckets_per_sec   
        read_objects_per_sec     
        write_objects_per_sec    
        others_per_sec           
        usec_per_read_bucket_op  
        usec_per_write_bucket_op 
        usec_per_read_object_op  
        usec_per_write_object_op 
        usec_per_other_op        
        time                        
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $EndTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Resolution,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $StartTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Type = $null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
};

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/arrays/s3-specific-performance";             
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($StartTime) {
                $uri.Add('start_time' , $StartTime)
        }
        if ($Resolution) {
                $uri.Add('resolution' , $Resolution)
        }
        if ($EndTime) {
                $uri.Add('end_time' , $EndTime)
        }
        if ($Type) {$
                Body.Add('Type' , $Type)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbBucket()
{
<#
.SYNOPSIS
        Lists array Buckets
.DESCRIPTION
        Helper function
        This function list S3 Buckets on the array
.EXAMPLE
        PS> Get-PfbBucket
        PS> Get-PfbBucket -Names '<name of bucket>'
        PS> Get-PfbBucket -Sort 'performance'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        TotalOnly (Not Mandatory)
        
.OUTPUTS
        bucket response       
        account
                name
                resource_type
        created
        destroyed
        id
        name
        object_count
        space
                data_reduction
                snapshots
                total_physical
                unique
                virtual
              
        time_remaining
        versioning
        
.NOTES
                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $TotalOnly 
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($Limit -gt 5)  { $Limit = 5; 
                write-host "Limit set to max of 5 due to API policy";}
        
        $url = "/api/$ApiVers/buckets";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        if ($TotalOnly) {
                $uri.Add('total_only' , $TotalOnly)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbBucket()
{
<#
.SYNOPSIS
        Adds S3 Buckets
.DESCRIPTION
        Helper function
        This function adds S3 Buckets to the array
.EXAMPLE
        PS> Add-PfbBucket -Names '<name of bucket>' -Account '<name of account>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Account (Not Mandatory)
        Namess (Not Mandatory)
                
.OUTPUTS
        bucket response       
        account
                name
                resource_type
        created
        destroyed
        id
        name
        object_count
        space
                data_reduction
                snapshots
                total_physical
                unique
                virtual
                      
        time_remaining
        versioning
                
.NOTES
        Bucket Names are unique, regardless of Account, you can only have one bucket of that name
        Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Account = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null
);

if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}


$body = @{
        'account' = @{ 
                'name'=$Account
        }
}	

        $url = "/api/$ApiVers/buckets";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbBucket()
{
<#
.SYNOPSIS
        Update array Buckets
.DESCRIPTION
        Helper function
        This function updates S3 Buckets on the array
.EXAMPLE
        Mark bucket for destruction
        PS> Update-PfbBucket -Names '<bucket name>' -Attributes  '{ "destroyed":"true" }'
        Recover bucket
        PS> Update-PfbBucket -Names '<bucket name>' -Attributes  '{ "destroyed":"false" }'
        Use JSON input from file.
        PS> Update-PfbBucket -Names '<bucket name>' -InputFile '<file name>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Attributes (Not Mandatory)     
        InputFile (Not Mandatory)      
              
.OUTPUTS
        bucket response       
                ccount
                name
                resource_type
        created
        destroyed
        id
        name
        object_count
        space
                data_reduction
                snapshots
                total_physical
                unique
                virtual
                      
        time_remaining
        versioning
                
.NOTES
                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
} else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/buckets";       
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('name' , $Names)
        }
        if ($Ids) {
                $uri.Add('ids' , $Ids)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbBucket()
{
<#
.SYNOPSIS
        Delete / Eradicate Buckets
.DESCRIPTION
        Helper function
        This function deletes / eradicates S3 Buckets on the array after they have been destroyed.
.EXAMPLE
        PS> Remove-PfbBucket -Names '<bucket name>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
                
.OUTPUTS
        bucket response       
        
.NOTES
                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
        $url = "/api/$ApiVers/buckets";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbBucketPerformance()
{
<#
.SYNOPSIS
        Get Buckets Performance
.DESCRIPTION
        Helper function
        This function gets S3 Buckets performance , it will only show 5 at a time
.EXAMPLE
        PS> Get-PfbBucketPerformance
        PS> Get-PfbBucketPerformance -Names 'bucket name'
        Start at 5th bucket 
        PS> Get-PfbBucketPerformance -Start 5
        Show only the totals
        PS> Get-PfbBucketPerformance -TotalOnly 1
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        End_Time (Not Mandatory)
        Start_Time (Not Mandatory)
        Names (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Total_Only (Not Mandatory)
        Resolution (Not Mandatory)    
                        
.OUTPUTS
        bucket response       
        bytes_per_op
        bytes_per_read
        bytes_per_write
        name
        others_per_sec
        read_bytes_per_sec
        reads_per_sec
        time
        usec_per_other_op
        usec_per_read_op
        usec_per_write_op
        write_bytes_per_sec
        writes_per_sec
                        
.NOTES
                                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $EndTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $StartTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = 5,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Resolution,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $TotalOnly
);
        if (!$FlashBlade) {
                $myreturn = $(Get-InternalPfbJson);
                $FlashBlade = $myreturn[0]
                $ApiToken = $myreturn[1]
                $ApiVers = $myreturn[2]
                $SkipCertificateCheck = $myreturn[3]
        }
        
        if ($SkipCertificateCheck -eq 'true') {
                $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
                if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
                $skipcert=$True
        }

	if ($Limit -gt 5)  { $Limit = 5; 
			write-host "Limit set to max of 5 due to API policy";}

                $headers = @{};
                $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));
                $url = "/api/$ApiVers/buckets/performance";

                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }
                if ($Ids) {
                        $uri.Add('ids', $Ids)
                }
                if ($Filter) {
                        $uri.Add('filter', $Filter)
                }
                if ($Sort) {
                        $uri.Add('sort' , $Sort)
                }
                if ($Start) {
                        $uri.Add('start' , $Start)
                }
                if ($Limit) {
                        $uri.Add('limit' , $Limit)
                }
                if ($Token) {
                        $uri.Add('token' , $Token)
                }
                if ($EndTime) {
                        $uri.Add('end_time' , $EndTime)
                }
                if ($StartTime) {
                        $uri.Add('start_time' , $StartTime)
                }
		if ($Resolution) {
                        $uri.Add('resolution' , $Resolution)
                } 
                if ($TotalOnly) {
                        $uri.Add('total_only' , $TotalOnly)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'GET' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Get-PfbBucketS3SpecificPerformance()
{
<#
.SYNOPSIS
        Get Buckets Performance
.DESCRIPTION
        Helper function
        This function gets S3 Buckets performance , it will only show 5 at a time
.EXAMPLE
        PS> Get-PfbBucketsPerformance
        PS> Get-PfbBucketS3SpecificPerformance -Names 'bucket name'
        Start at 5th bucket 
        PS> Get-PfbBucketS3SpecificPerformance -Start 5
        Show only the totals
        PS> Get-PfbBucketS3SpecificPerformance -TotalOnly 1
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        End_Time (Not Mandatory)
        Start_Time (Not Mandatory)
        Names (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Total_Only (Not Mandatory)
        Resolution (Not Mandatory)    
                        
.OUTPUTS
        bucket response       
        bytes_per_op
        bytes_per_read
        bytes_per_write
        name
        others_per_sec
        read_bytes_per_sec
        reads_per_sec
        time
        usec_per_other_op
        usec_per_read_op
        usec_per_write_op
        write_bytes_per_sec
        writes_per_sec
                        
.NOTES
        I think this is the same as buckets performance, have asked if I can remove/delete it                                   
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $EndTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $StartTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = 5,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Resolution,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $TotalOnly
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}


if ($Limit -gt 5)  { $Limit = 5; 
                write-host "Limit set to max of 5 due to API policy";}

        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));
        $url = "/api/$ApiVers/buckets/performance";

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }
        if ($EndTime) {
                $uri.Add('end_time' , $EndTime)
        }
        if ($StartTime) {
                $uri.Add('start_time' , $StartTime)
        }
        if ($Resolution) {
                $uri.Add('resolution' , $Resolution)
        } 
        if ($TotalOnly) {
                $uri.Add('total_only' , $TotalOnly)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbCertificate()
{
<#
.SYNOPSIS
	List certificates and attributes. The passphrase and private_key parameters will not be displayed in the response.
.DESCRIPTION
	Helper function
        List certificates and attributes. The passphrase and private_key parameters will not be displayed in the response.
.EXAMPLE
        PS> Get-PfbCertificate
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        IDs (Not Mandatory)
        Names (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

.OUTPUTS
        certificate
        common_name
        country
        email
        common_name
        intermediate_certificate 
        issued_by                
        issued_to                
        key_size                 
        locality                 
        name                     
        organization             
        organizational_unit      
        state                    
        status                   
        valid_from               
        valid_to                 
        id                       
        certificate_type

.NOTES
	Tested
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificates";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty);

        if ($Names) {
                $uri.Add('names', $Names)
        };
        if ($Ids) {
                $uri.Add('ids', $Ids)
        };
        if ($Filter) {
                $uri.Add('filter', $Filter)
        };
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        };
        if ($Start) {
                $uri.Add('start' , $Start)
        };
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        };
        if ($Token) {
                $uri.Add('token' , $Token)
        };

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbCertificate()
{
<#
.SYNOPSIS
        Uploads a CA certificates.
.DESCRIPTION
        Helper function
        This function uploads CA certificates to the array. 
        Certificate can be added in the form of an -Attribute input or input from Json File
.EXAMPLE
        PS> Add-PfbCertificate -Names 'Certificate Name' -Attributes ' {"certificate":"<certificate> }'
        PS> Add-PfbCertificate -Names 'Certificate Name' -InputFile 'File Name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Mandatory)
        Attributes (Not Mandatory)
        InputFile (Not Mandatory)

.OUTPUTS
        certificate response       
.NOTES
        Not Tested        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
} else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

#$body = @{
#        certificate=$Certificate
#}

        $url = "/api/$ApiVers/certificates";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty);

        if ($Names) {
                $uri.Add('names', $Names)
        };

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbCertificate()
{
<#
.SYNOPSIS
        Modifies an existing certificates.
.DESCRIPTION
        Helper function
        This function modifies certificates on the array.
.EXAMPLE
        PS> Update-PfbCertificate
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
.OUTPUTS
        certificate response       
.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
} else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
        
        $url = "/api/$ApiVers/certificates";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty);

        if ($Names) {
                $uri.Add('names', $Names)
        };
        if ($Ids) {
                $uri.Add('names', $Ids)
        };

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbCertificate()
{
<#
.SYNOPSIS
        Deletes array certificates.
.DESCRIPTION
        Helper function
        This function deletes certificates from the array.
.EXAMPLE
        PS> Remove-PfbCertificate -Names '<certificate name>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
.OUTPUTS
        certificate response       
.NOTES
        Not Tested                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}
        
if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificates";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty);

        if ($Names) {
                $uri.Add('names', $Names)
        };
        if ($Ids) {
                $uri.Add('names', $Ids)
        };

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbCertificatesUse()
{
<#
.SYNOPSIS
        Lists array certificates uses.
.DESCRIPTION
        Helper function
        This function list certificate uses, being used by what
.EXAMPLE
        PS> Get-PfbCertificateUse
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

.OUTPUTS
        certificates groups response       
        group
                id
                name
                use
                        id
                        name
                        resource_type
.NOTES
        Tested                           
#>

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][Int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][Int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificates/uses";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbCertificateGroup()
{
<#
.SYNOPSIS
        Lists Array Certificates Groups.
.DESCRIPTION
        Helper function
        This function list certificate groups on the array.
.EXAMPLE
        PS> Get-PfbCertificateGroup
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        CertificateIds (Not Mandatory)
        CertificateGroupIds (Not Mandatory)
        CertificateNames (Not Mandatory)
        CertificateGroupNames (Not Mandatory)

.OUTPUTS
        certificates groups response       
        group
                id
                name
                resource_type
        member
                id
                name
                resource_type
.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateIds =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][Int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][Int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificates/certificate-groups";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }
        if ($CertificateIds) {
                $uri.Add('certificate_ids' , $CertificateIds)
        }
        if ($CertificateGroupIds) {
                $uri.Add('certificate_group_cids' , $CertificateGroupIds)
        }
        if ($CertificateNames) {
                $uri.Add('certificate_names' , $Certificate_Names)
        }
        if ($CertificateGroupNames) {
                $uri.Add('certificate_group_names' , $CertificateGroupNames)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbCertificateGroup()
{
<#
.SYNOPSIS
        Add Array Certificates Groups.
.DESCRIPTION
        Helper function
        This function adds certificate groups on the array.
.EXAMPLE
        PS> Add-PfbCertificateGroup -CertificateIds '<certificate id>' -CertificateGroupNames '<group name>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        CertificateIds (Not Mandatory)
        CertificateGroupIds (Not Mandatory)
        CertificateNames (Not Mandatory)
        CertificateGroupNames (Not Mandatory)

.OUTPUTS
        certificates groups response       
        group
                id
                name
                resource_type
        member
                id
                name
                resource_type
.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupNames = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificates/certificate-groups";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($CertificateIds) {
                $uri.Add('certificate_ids' , $CertificateIds)
        }
        if ($CertificateGroupIds) {
                $uri.Add('certificate_group_ids' , $CertificateGroupIds)
        }
        if ($CertificateNames) {
                $uri.Add('certificate_names' , $CertificateNames)
        }
        if ($CertificateGroupNames) {
                $uri.Add('certificate_group_names' , $CertificateGroupNames)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbCertificateGroup()
{
<#
.SYNOPSIS
        Remove one or more certificates from one or more groups.
.DESCRIPTION
        Helper function
        This function will remove one or more certificates from one or more groups.
        Requires the certificate_names or certificate_ids parameter with the certificate_group_ids or certificate_group_names parameter.
.EXAMPLE
        PS> Remove-PfbCertificateGroup -Certificate_Ids 'certificate ID' -Certificate_Group_Names 'Cwrtificate Group Name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        CertificateIds (Not Mandatory)
        CertificateGroupIds (Not Mandatory)
        CertificateNames (Not Mandatory)
        CertificateGroupNames (Not Mandatory)

.OUTPUTS
        certificates groups response       
        group
                id
                name
                resource_type
        member
                id
                name
                resource_type
.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateIds,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupIds,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateNames,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupNames

);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificates/certificate-groups";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));
        
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($CertificateIds) {
                $uri.Add('certificate_ids' , $CertificateIds)
        }
        if ($CertificateGroupIds) {
                $uri.Add('certificate_group_ids' , $CertificateGroupIds)
        }
        if ($CertificateNames) {
                $uri.Add('certificate_names' , $CertificateNames)
        }
        if ($CertificateGfoupNames) {
                $uri.Add('certificate_group_names' , $CertificateGroupNames)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbCertificateGroupCertificate()
{
<#
.SYNOPSIS
        Lists Array Certificate Groups Certificates.
.DESCRIPTION
        Helper function
        This function list certificate groups on the array.
.EXAMPLE
        PS> Get-PfbCertificateGroupsCertificate
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        CertificateIds (Not Mandatory)
        CertificateGroupIds (Not Mandatory)
        CertificateNames (Not Mandatory)
        CertificateGroupNames (Not Mandatory)

.OUTPUTS
        certificates groups certificates response       
        group
                id
                name
                resource_type
        member
                id
                name
                resource_type
.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificate-groups/certificates";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }
        if ($CertificateIds) {
                $uri.Add('certificate_ids' , $CertificateIds)
        }
        if ($CertificateGroupIds) {
                $uri.Add('certificate_group_ids' , $CertificateGroupIds)
        }
        if ($CertificateNames) {
                $uri.Add('certificate_names' , $CertificateNames)
        }
        if ($CertificateGroupNames) {
                $uri.Add('certificate_group_names' , $CertificateGroupNames)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbCertificateGroupCertificate()
{
<#
.SYNOPSIS
        Add one or more certificates to one or more groups
.DESCRIPTION
        Helper function
        This function adds certificate to certificate groups on the array.
.EXAMPLE
        Add a certificate to a group
        PS> Add-PfbCertificateGroupCertificate -CertificateIds '<certificate ID>' -CertificateGroupNames '<group name>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        CertificateIds (Not Mandatory)
        CertificateGroupIds (Not Mandatory)
        CertificateNames (Not Mandatory)
        CertificateGroupNames (Not Mandatory)

.OUTPUTS
        certificates groups certificates response       
        group
                id
                name
                resource_type
        member
                id
                name
                resource_type
.NOTES
        Requires the certificate_names or certificate_ids parameter with the certificate_group or certificate_group_names parameter.
        Requires the x-auth-token header returned by the POST login request that created the REST session.
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupNames = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificate-groups/certificates";
       $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($CertificateIds) {
                $uri.Add('certificate_ids' , $CertificateIds)
        }
        if ($CertificateGroupIds) {
                $uri.Add('certificate_group_ids' , $CertificateGroupIds)
        }
        if ($CertificateNames) {
                $uri.Add('certificate_names' , $CertificateNames)
        }
        if ($CertificateGroupNames) {
                $uri.Add('certificate_group_names' , $CertificateGroupNames)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbCertificateGroupCertificate()
{
<#
.SYNOPSIS
        Remove one or more certificates from one or more groups.
.DESCRIPTION
        Helper function
        This function removes certificate groups on the array.
.EXAMPLE
        Add a certificate to a group
        PS> Remove-PfbCertificateGroupCertificate -CertificateIds 'certificate ID' -CertificateGroupNames 'group name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        CertificateIds (Not Mandatory)
        CertificateGroupIds (Not Mandatory)
        CertificateNames (Not Mandatory)
        CertificateGroupNames (Not Mandatory)

.OUTPUTS
        certificates groups certificates response       
        group
                id
                name
                resource_type
        member
                id
                name
                resource_type
.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupIds = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $CertificateGroupNames = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificate-groups/certificates";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($CertificateIds) {
                $uri.Add('certificate_ids' , $CertificateIds)
        }
        if ($CertificateGroupIds) {
                $uri.Add('certificate_group_ids' , $CertificateGroupIds)
        }
        if ($CertificateNames) {
                $uri.Add('certificate_names' , $CertificateNames)
        }
        if ($CertificateGroupNames) {
                $uri.Add('certificate_group_names' , $CertificateGroupNames)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbCertificateGroupsUse()
{
<#
.SYNOPSIS
        List how certificates are being used and by what.
.DESCRIPTION
        Helper function
        This function list certificate group uses, being used by what
.EXAMPLE
        PS> Get-PfbCertificateGroupUse
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

.OUTPUTS
        certificates groups uses response       
        group
                id
                name
                use
                        id
                        name
                        resource_type
.NOTES
         Tested                       
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null, 
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][Int32] $Limit ,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/certificate-groups/uses";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids){ 
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbDirectoryService()
{
<#
.SYNOPSIS
        Lists Directory Services
.DESCRIPTION
        Helper function
        This function list Directory Services.
.EXAMPLE
        PS> Get-PfbDirectoryService
        PS> Get-PfbDirectoryService -Filter 'enabled="false"'
        PS> Get-PfbDirectoryService -Filter 'name="management"'
        PS> Get-PfbDirectoryService -Test 1 -Names 'name to test'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Test (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

.OUTPUTS
        directory services response       
        base_dn
        bind_user
        ca_certificate
                id
                name
                resource_type
      
        ca_certificate_group
                id
                name
                resource_type
      
        enabled
                id
                name
                nfs
                        nis_domains
                        nis_servers
      
        services
                management
        smb
                join_ou
      
        uris
                ldap

.NOTES
       Tested                 
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Test,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        if ($Test) { 
                $url = "/api/$ApiVers/directory-services/test";
        } else {
                $url = "/api/$ApiVers/directory-services";
        }

        #$url = "/api/$ApiVers/directory-services";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Limit) {$
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbDirectoryService()
{
<#
.SYNOPSIS
        Modify directory service attributes (use Names or IDs not both) input from json file
.DESCRIPTION
        Helper function
        This function modifies directory service attributes (use Names or IDs not both) input from json file
.EXAMPLE
        PS> Update-PfbDirectoryService -Names 'services name' -Attributes '{ "Keys":{"key":"value1", "Key":"value2"} }'
        If you want to change it to read from a file
        PS> Update-PfbDirectoryService -Names 'services name' -FileName 'file name of Json file with content in it'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Attributes (Not Mandatory)

.OUTPUTS
        directory services response       
        base_dn
        bind_user
        ca_certificate
                id
                name
                resource_type
      
        ca_certificate_group
                id
                name
                resource_type
      
        enabled
                id
                name
                nfs
                        nis_domains
                        nis_servers
      
        services
                management
        smb
                join_ou
      
        uris
                ldap

.NOTES
You can modify the $body variable to read from a file below - its commented out
Example JSON for file to remove an organizational unit (OU) from the SMB services
{
  "smb": {
    "join_ou": ""
   } 
}
Example JSON to configure NIS
{
  "nfs": {
    "nis_domains": [
      "ypdomain"
    ],
    "nis_servers": [
      "181.44.543.12",
      "hostname.example.com"
    ] 
  }
}
Please see Rest API guide for more examples
       Not Tested                 
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
               
if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/directory-services";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Limit) {$
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbDirectoryServiceRole()
{
<#
.SYNOPSIS
        List the role-based access control (RBAC) group configuration settings for manageability.
.DESCRIPTION
        Helper function
        This function lists array Directory Services Roles
.EXAMPLE
        PS> Get-PfbDirectoryServiceRole
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

.OUTPUTS
        directory services roles response       
        group
        group_base
        id
        name

.NOTES
                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/directory-services/roles";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbDirectoryServiceRole()
{
<#
.SYNOPSIS
        Modify the role-based access control (RBAC) group configuration settings for manageability.
.DESCRIPTION
        Helper function
        Modify the role-based access control (RBAC) group configuration settings for manageability. 
        Anonymous bind user is supported for NFS protocols. If implementing anonymous bind user, the bind_user and bind_password fields must be left blank.
.EXAMPLE
        PS> Update-PfbDirectoryServicesRoles -Names 'manager' -Attributes '{ "Keys":{"key":"value1", "Key":"value2"} }'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

.OUTPUTS
        directory services roles response       
        group
        group_base
        id
        name

.NOTES
        Not Tested       
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
                
        $url = "/api/$ApiVers/directory-services/roles";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $body = ConvertFrom-Json $Attributes -AsHashtable;

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbFilesystem()
{
<#
.SYNOPSIS
        Lists FlashBlade file systems. Can be filtered, or sorted to suit
.DESCRIPTION
        Helper function
        This function lists file systems on the array
        With no names parameter, lists all file systems. With the names parameter, lists the attributes for the specified file system or file systems.
.EXAMPLE
        PS> Get-PfbFilesystem
        PS> Get-PfbFilesystem -Filter 'hard_limit_enabled="true"'
        PS> Get-PfbFilesystem -Sort 'name' -Limit 10
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

.OUTPUTS
        file systems response       
        created
        destroyed
        fast_remove_directory_enabled
        hard_limit_enabled
        http
                enabled"
      
        id
        name
        nfs
                enabled
                rules
                v3_enabled
                v4_1_enabled
      
        provisioned
        smb
                acl_mode
        enabled
      
        snapshot_directory_enabled
        space
                data_reduction
                snapshots
                total_physical
                unique
                virtual
      
        time_remaining

.NOTES
        Tested                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/file-systems";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbFilesystem()
{
<#
.SYNOPSIS
        Creates a file system on the current array.
.DESCRIPTION
        Helper function
        This function Creates a file system on the current array
        
.EXAMPLE
        PS> Add-PfbFilesystem -InputFile 'name of JSON file'
        PS> Add-PfbFilesystem  -Attributes '{"name":"powershell","provisioned":"10000","nfs":{"v3_enabled":"true"} } '

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystem (Not Mandatory)

.OUTPUTS
        file systems response       
        created
        destroyed
        fast_remove_directory_enabled
        hard_limit_enabled
        http
                enabled"
      
        id
        name
        nfs
                enabled
                rules
                v3_enabled
                v4_1_enabled
      
        provisioned
        smb
                acl_mode
        enabled
      
        snapshot_directory_enabled
        space
                data_reduction
                snapshots
                total_physical
                unique
                virtual
      
        time_remaining

.NOTES
        Tested
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/file-systems";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        # $body = @{ name = $Names };

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbFilesystem()
{
<#
.SYNOPSIS
        Modifies the attributes for the file system
.DESCRIPTION
        Helper function
        This function Modifies the attributes for the file system
        Requires the name parameter.
        
.EXAMPLE
        PS> Update-PfbFilesystem -Names 'name of file-system'
        PS> Update-PfbFilesystem -FileNames 'name of JSON file'
        PS> Update-PfbFilesystem -Attributes '{ "key":"value1", "Key":"value2" }'
        PS> Update-PfbFilesystem -Attributes '{ "Keys":{"key":"value1", "Key":"value2"} }'
        PS> Update-PfbFilesystem -Names 'name' -Attributes '{ "nfs":{"enabled":"true", "v3_enabled":"true"} } '
        PS> Update-PfbFilesystem -Names 'name' -Attributes '{"destroyed":"true" } '
        PS> Update-PfbFilesystem -Names 'powershell' -Attributes '{"nfs":{"v3_enabled":"false"},"destroyed":"true" } '
        
        Provisioned sizes are always in bytes

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Attributes (Not Mandatory)
        InputFile (Not Mandatory)
        IDs (Not Mandatory)
        IgnoreUsage (Not Mandatory)
        Names (Not Mandatory)

.OUTPUTS
        file systems response       
        created
        destroyed
        fast_remove_directory_enabled
        hard_limit_enabled
        http
                enabled"
      
        id
        name
        nfs
                enabled
                rules
                v3_enabled
                v4_1_enabled
      
        provisioned
        smb
                acl_mode
        enabled
      
        snapshot_directory_enabled
        space
                data_reduction
                snapshots
                total_physical
                unique
                virtual
      
        time_remaining

.NOTES
        Not Tested
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $IgnoreUsage
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
        
        $url = "/api/$ApiVers/file-systems";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));
        
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('name' , $Names)
        }
        if ($Ids) {
                $uri.Add('ids' , $Ids)
        }
        if ($IgnoreUsage) {
                $uri.Add('ignore_usage' , $IgnoreUsage)
        }
        #$body = ConvertFrom-Json $Attributes -AsHashtable;

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbFilesystem()
{
<#
.SYNOPSIS
        Deletes a file system
.DESCRIPTION
        Helper function
        This function Deletes file system once it has been destroyed with the Update-PfbFileSystems command
        Requires the name parameter.
        
.EXAMPLE
        PS> Remove-PfbFilesystem -Names '<name of file-system>'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        IDs (Not Mandatory)
        Name (Not Mandatory)

.OUTPUTS
        file systems response       
        {}

.NOTES
        Not Tested - to complete

#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/file-systems";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('name', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbFilesystemPerformance()
{
<#
.SYNOPSIS
        Lists Arrays Filesystems Performance
.DESCRIPTION
        Helper function
        This function lists FlashBlade Filesystem Performance Information at a given time period
        Displays the performance statistics for the specified file system or file systems. 
        Performance statistics are limited to displaying a maximum of five or fewer file systems at any given time. 
        Due to the API rules, the query parameters will limit the results to five or less file systems which is the max.
        If you add a start paramater, to start at whatever number you like.

.EXAMPLE
        PS> Get-PfbFilesystemsPerformance -Protocol 'nfs'
        PS> Get-PfbFilesystemsPerformance -Protocol 'nfs' -Names 'file-system Name' -Start 6
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        End_Time (Not Mandatory)
        Resolution (Not Mandatory)
        Start_Time (Not Mandatory)
        Protocol (Not Mandatory)
        Type (Not Mandatory)
        Limit (Not Mandatory)
        Filter (Not Mandatory)
        Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Total_Only (Not Mandatory)
                        
.OUTPUTS
        Performance response       
        name                
        writes_per_sec      
        reads_per_sec       
        others_per_sec      
        usec_per_write_op   
        usec_per_read_op    
        usec_per_other_op   
        read_bytes_per_sec  
        write_bytes_per_sec 
        time                
        bytes_per_read     
        bytes_per_write     
        bytes_per_op        
        output_per_sec      
        input_per_sec       
.NOTES
        Resoloution : The time between performance samples (in milliseconds since epoch). 
        Available resolutions may depend on the data types start_time and end_time. 
        Accepted millisecond values are: 30000 (30 sec), 300000 (5 mins), 1800000 (30 mins), 7200000 (2 hrs), and 86400000 (24 hrs).
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $EndTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][long] $StartTime,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Protocol = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = 5,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Resolution = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Total_Only
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

	if ($Limit -gt 5)  { $Limit = 5; 
			write-host "Limit set to max of 5 due to API policy";}
                
        $url = "/api/$ApiVers/file-systems/performance";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Protocol) {
                $uri.Add('protocol', $Protocol)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }
        if ($EndTime) {
                $uri.Add('end_time' , $EndTime)
        }
        if ($StartTime) {
                $uri.Add('start_time' , $StartTime)
        }
        if ($Resolution) {
                $uri.Add('resolution' , $Resolution)
        } 
        if ($Total_Only) {
                $uri.Add('total_only' , $Total_Only)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbFilesystemPolicies()
{
<#
.SYNOPSIS
        Lists all file systems mapped to a snapshot scheduling policy.
.DESCRIPTION
        Helper function
        This function lists all file systems mapped to a snapshot scheduling policy.
.EXAMPLE
        PS> Get-PfbFilesystemPolicies
        PS> Get-PfbFilesystemPolicies -Policy_Names 'policy name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        MemberIDs (Not Mandatory)
        Member_Names (Not Mandatory)
        PolicyIDs (Not Mandatory)
        Policy_Names (Not Mandatory)
        
.OUTPUTS
        file systems policy response       
        Member
                id
                name
                Resource

        Policy
                id
                name
                resource
        
.NOTES
        Tested               
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Lmit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
        $url = "/api/$ApiVers/file-systems/policies";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($MemberNames) {
                $uri.Add('member_names' , $MemberNames)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names' , $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids' , $PolicyIDs)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids' , $MemberIDs)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbFilesystemPolicies()
{
<#
.SYNOPSIS
        Map a file system to a snapshot scheduling policy.
.DESCRIPTION
        Helper function
        
        Map a file system to a snapshot scheduling policy. Only one file system can be mapped to a policy at a time. 
        This endpoint has the same functionality as the POST /polices/file-systems endpoint.
.EXAMPLE
        PS> Add-PfbFilesystemPolicies -PolicyNames '<policy name>' -MemberNames '<member names>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        MemberIDs (Not Mandatory)
        MemberNames (Not Mandatory)
        PolicyIDs (Not Mandatory)
        PolicyNames (Not Mandatory)
        
.OUTPUTS
        file systems policy response       
        Member
                id
                name
                Resource

        Policy
                id
                name
                resource
        
.NOTES
        Tested               
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
        $url = "/api/$ApiVers/file-systems/policies";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($MemberNames) {
                $uri.Add('member_names' , $MemberNames)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names' , $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids' , $Policy_ids)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids' , $MemberIDs)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbFilesystemPolicies()
{
<#
.SYNOPSIS
        Remove a file system to a snapshot scheduling policy.
.DESCRIPTION
        Helper function
        
        Map a file system to a snapshot scheduling policy. Only one file system can be mapped to a policy at a time. 
        This endpoint has the same functionality as the POST /polices/file-systems endpoint.
.EXAMPLE
        PS> Remove-PfbFilesystemsPolicies -Member_Names 'Mmember name>' -Policy_Names <policy names>
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        MemberIDs (Not Mandatory)
        MemberNames (Not Mandatory)
        PolicyIDs (Not Mandatory)
        PolicyNames (Not Mandatory)
        
.OUTPUTS
        file systems policy response       
        Member
                id
                name
                Resource

        Policy
                id
                name
                resource
        
.NOTES
        Tested               
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
                $url = "/api/$ApiVers/file-systems/policies";
                $link = "https://$FlashBlade$url";
		$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($MemberNames) {
                        $uri.Add('member_names' , $MemberNames)
                }
                if ($PolicyNames) {
                        $uri.Add('policy_names' , $PolicyNames)
                }
                if ($PolicyIDs) {
                        $uri.Add('policyids' , $Policy_ids)
                }
                if ($MemberIDs) {
                        $uri.Add('member_ids' , $MemberIDs)
                }
                
                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'DELETE' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Get-PfbFilesystemSnapshot()
{
<#
.SYNOPSIS
        Lists array file system snapshots
.DESCRIPTION
        Helper function
        This function lists array file system snapshots
.EXAMPLE
        PS> Get-PfbFilesystemSnapshot
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Names_or_Sources (Not Mandatory)
        
.OUTPUTS
        file systems snapshots response       
        name
        suffix
        created
        source
        source_id
        policy
                name
                id
                resource_type
        destroyed
        source_destroyed
        time_remaining
        id
        
.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Lmit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names_or_Sources = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/file-system-snapshots";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Names_or_Sources) {
                $uri.Add('names_or_sources' , $Names_or_Sources)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Add-PfbFilesystemSnapshot()
{
<#
.SYNOPSIS
        This function creates a file system snapshots from a source file system
.DESCRIPTION
        Helper function
        Creates snapshots for the specified source file systems. 
        If a source file system is not specified, creates snapshots for all file systems on the array.
.EXAMPLE
        PS> Add-PfbFilesystemSnapshots -Sources '<source filesystem name>' -Suffix '<optional suffix>
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Sources ( Mandatory)
        Suffix (Not Mandatory)
        
.OUTPUTS
        file systems snapshots response       
        name
        suffix
        created
        source
        source_id
        policy
                name
                id
                resource_type
        destroyed
        source_destroyed
        time_remaining
        id
        
.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Sources = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Suffix = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/file-system-snapshots";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty);

        if ($Sources) {
                $uri.Add('sources', $Sources)
        }

        if ($Suffix) {
                $body =  @{ 'suffix' = $Suffix } ;
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbFilesystemSnapshot()
{
<#
.SYNOPSIS
        Modifies the Attributes for the File System Snapshot
.DESCRIPTION
        Helper function
        This function Modifies the Attributes for the File System Snapshot
.EXAMPLE
        PS> Update-PfbFilesystemsSnapshots -Names 'test.1234' -Attributes '{ "destroyed":"true" }'
        PS> Update-PfbFilesystemsSnapshots -Names 'test.1234' -Attributes '{ "destroyed":"false" }'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Mandatory)
        Attributes (Not Mandatory)
        IDs (Not Mandatory)
        
.OUTPUTS
        file systems snapshots response       
        name
        suffix
        created
        source
        source_id
         policy
                name
                id
                resource_type
        destroyed
        source_destroyed
        time_remaining
        id
        
.NOTES
        Tested                      
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
$myreturn = $(Get-InternalPfbJson);
$FlashBlade = $myreturn[0]
$ApiToken = $myreturn[1]
$ApiVers = $myreturn[2]
$SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
        $url = "/api/$ApiVers/file-system-snapshots";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('name' , $Names)
        }
        if ($Ids) {
                $uri.Add('ids' , $Ids)
        }

        $body = ConvertFrom-Json $Attributes -AsHashtable;

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbFilesystemSnapshot()
{
<#
.SYNOPSIS
        Deletes A File System Snapshots
.DESCRIPTION
        Helper function
        This function deletes a file system snapshots
.EXAMPLE
        PS> Remove-PfbFilesystemSnapshot -Names 'testsnap.1234'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        
.OUTPUTS
        {}       
 
.NOTES
        Snapshot needs to be destroyed via Update-PfbFilesystemSnapshot command first
        At some point I think I will add a force to destroy first, then delete in one command.
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/file-system-snapshots";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('name', $Names)
        }
        if ($Ids) {
                $uri.Add('ids' , $Ids)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbFilesystemSnapshotPolicies()
{
<#
        .SYNOPSIS
                List file system snapshots mapped to snapshot scheduling policies.
        .DESCRIPTION
                Helper function
                This function lists array file system snapshot policies
        .EXAMPLE
                PS> Get-PfbFilesystemSnapshotPolicies
        .INPUTS
                FlashBlade (Not Mandatory)
                APIToken (Not Mandatory)
                Names (Not Mandatory)
                IDs (Not Mandatory)
                Filter (Not Mandatory)
                Limit (Not Mandatory)
                Sort (Not Mandatory)
                Start (Not Mandatory)
                Token (Not Mandatory)
                MemberIDs (Not Mandatory)
                Member_Names (Not Mandatory)
                PolicyIDs (Not Mandatory)
                Policy_Names (Not Mandatory)
        
        .OUTPUTS
                file systems snapshot policy response       
                Member
                        id
                        name
                        Resource

                Policy
                        id
                        name
                        resource
        
.NOTES
        Tested - but we have no policies set up                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/file-system-snapshots/policies";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($MemberNames) {
                $uri.Add('member_names' , $MemberNames)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names' , $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids' , $Policy_ids)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids' , $MemberIDs)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbBlade()
{
<#
.SYNOPSIS
        Lists Blades information
.DESCRIPTION
        Helper function
        This function lists FlashBlade Blades and status
.EXAMPLE
        PS> Get-PfbBlade
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        Blades Response       
                
.NOTES
        Tested                                       
#>
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/blades";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        
        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}
 
function Get-PfbHardware()
{
<#
.SYNOPSIS
        Lists all hardware component information
.DESCRIPTION
        Helper function
        This function lists FlashBlade hardware component information
.EXAMPLE
        PS> Get-PfbHardware
        PS> Get-PfbHardware  -Filter "type = 'fan'"
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        Hardware response       
                
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
        $url = "/api/$ApiVers/hardware"; 
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}
function Update-PfbHardware()
{
<#
.SYNOPSIS
        Modifies the attributes associated with the hardware components.
.DESCRIPTION
        Helper function
        This function Modifies the attributes associated with the hardware components.
.EXAMPLE
        PS> Update-PfbHardware -Names 'CH1' -Attributes ' {"identify_enabled":"true"} '
        PS> Update-PfbHardware -Names 'CH1' -Attributes ' {"identify_enabled":"false"} '
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Attributes (Not Mandatory)
                        
.OUTPUTS
        Hardware response       
                
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
        
        $url = "/api/$ApiVers/hardware"; 
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $body = (ConvertFrom-Json $Attributes -AsHashtable)

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbHardwareConnector()
{
<#
.SYNOPSIS
        Lists all Hardware Connectors
.DESCRIPTION
        Helper function
        This function lists FlashBlade Hardware Connectors
.EXAMPLE
        PS> Get-PfbHardwareConnector
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        Hardware Connectors Response       
                
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $uri = "/api/$ApiVers/hardware-connectors";

        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));
        $link = "https://$FlashBlade$uri";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbHardwareConnector()
{
<#
.SYNOPSIS
        Modifies the array connection configuration.
.DESCRIPTION
        Helper function
        This function Modifies the array connection configuration.
.EXAMPLE
        PS> Update-PfbHardwareConnector -Names 'FM1.ETH1' -PortCount 4 -LaneSpeed 10000
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        LaneSpeed (Mandatory)
        PortCount (Mandatory)
                        
.OUTPUTS
        Hardware Connectors Response       
                
.NOTES
        Not Tested    
        Not sure if I should make this the same "attributes" format as the rest for input                                    
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][int32] $LaneSpeed = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][int32] $PortCount = $null

);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $uri = "/api/$ApiVers/hardware-connectors";

        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));
        $link = "https://$FlashBlade$uri";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $body = @{ 'lane_speed' = $LaneSpeed } , @{ 'port_count' = $PortCount } 

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-NOPfbLogs()
{
<#
.SYNOPSIS
        Lists all Array Logs
.DESCRIPTION
        Helper function
        A history of log events from the array is collected and downloaded to provide to the Pure Storage Support team for analysis. 
        A start and end time period must be specified for the collection of log events. The GET request returns an encrypted file using the application/octet-stream response. 
        Select Send and Download, then save as a zip file and send the log events to the Pure Storage Support team.
.EXAMPLE
        PS> Get-Pfblogs
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        Logs response       
                
.NOTES
        Specify the time period in milliseconds.  
        Stil' working on how to do this.    
        Incomplete                                  
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][Int64] $EndTime = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][Int64] $StartTime = $null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
                $url = "/api/$ApiVers/logs";
                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($StartTime) {
                        $uri.Add('start_time' , $StartTime)
                }
                if ($EndTime) {
                        $uri.Add('end_time' , $EndTime)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'GET' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Get-PfbDns()
{
<#
.SYNOPSIS
        Lists all Array DNS information
.DESCRIPTION
        Helper function
        This function lists FlashBlade DNS information
.EXAMPLE
        PS> Get-PfbDns
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        DNS response       
                
.NOTES
                                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/dns";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        
        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbDns()
{
<#
.SYNOPSIS
        Updates Array DNS information
.DESCRIPTION
        Helper function
        This function lists FlashBlade DNS information
.EXAMPLE
        PS> Update-PfbDns -Attributes '{"domain": "pure_dns_example.org", "nameservers": [ "10.64.12.6", "10.10.12.6"  ], "search": [ "restapi_example.org","pure_example.org" ] }'
        PS> Update-PfbDns -InputFile '<filename>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        DNS response       
                
.NOTES
        Not Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
} else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
                
        $url = "/api/$ApiVers/dns";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbLag()
{
<#
.SYNOPSIS
        Lists FlashBlade link aggregation groups and attributes
.DESCRIPTION
        Helper function
        This function lists FlashBlade Link Aggregation Group (LAG) information
.EXAMPLE
        PS> Get-PfbLag
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        LAGs response       
                
.NOTES
        Tested                                      
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
                $url = "/api/$ApiVers/link-aggregation-groups";
                $headers = @{};
                $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }
                if ($Ids) {
                        $uri.Add('ids', $Ids)
                }
                if ($Filter) {
                        $uri.Add('filter', $Filter)
                }
                if ($Sort) {
                        $uri.Add('sort' , $Sort)
                }
                if ($Start) {
                        $uri.Add('start' , $Start)
                }
                if ($Limit) {
                        $uri.Add('limit' , $Limit)
                }
                if ($Token) {
                        $uri.Add('token' , $Token)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'GET' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Add-PfbLag()
{
<#
.SYNOPSIS
        Adds FlashBlade link aggregation groups and attributes
.DESCRIPTION
        Helper function
        This function Adds FlashBlade Link Aggregation Group (LAG) information
.EXAMPLE
        PS> Add-PfbLag -Names '<lag name>' -Attributes '{ "ports": [ { "name": "CH3.FM1.ETH1" }, { "name": "CH3.FM1.ETH2" }, { "name": "CH3.FM1.ETH3" }, { "name": "CH3.FM1.ETH4"} ] }'
        PS> Add-PfbLag -InputFile '<filename?'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
        Attributes (Mandatory)
                        
.OUTPUTS
        LAGs response       
                
.NOTES
        Not Tested                                      
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
                
        $url = "/api/$ApiVers/link-aggregation-groups";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }  

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbLag()
{
<#
.SYNOPSIS
        Updates FlashBlade link aggregation groups and attributes
.DESCRIPTION
        Helper function
        This function updates FlashBlade Link Aggregation Group (LAG) information
.EXAMPLE
        PS> Update-PfbLag -Names '<lag name>' -Attributes '{ "ports": [ { "name": "CH3.FM1.ETH1" }, { "name": "CH3.FM1.ETH2" }, { "name": "CH3.FM1.ETH3" }, { "name": "CH3.FM1.ETH4"} ] }'
        PS> Update-PfbLag -InputFile '<filename>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
        Attributes (Mandatory)
                        
.OUTPUTS
        LAGs response       
                
.NOTES
        Not Tested                                   
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
                
        $url = "/api/$ApiVers/link-aggregation-groups";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbLag()
{
<#
.SYNOPSIS
        Removes FlashBlade link aggregation groups and attributes
.DESCRIPTION
        Helper function
        This function deletes FlashBlade Link Aggregation Groups 
.EXAMPLE
        PS> Remove-PfbLag -Names '<lag name>' 

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Not Mandatory)
        IDs ( Not Mandatory)
                        
.OUTPUTS
        LAGs response       
                
.NOTES
        Not Tested                                      
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
        $url = "/api/$ApiVers/link-aggregation-groups";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}


function Get-PfbNetworkInterface()
{
<#
.SYNOPSIS
        Lists all Network Interfaces
.DESCRIPTION
        Helper function
        This function lists FlashBlade Network Interfaces
.EXAMPLE
        PS> Get-PfbNetworkInterface
        PS> Get-PfbNetworkInterface -Filter 'address="<IP>"'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        Network Interfaces response       
                
.NOTES
       Tested                                         
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

                $url = "/api/$ApiVers/network-interfaces"; 
                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }
                if ($Ids) {
                        $uri.Add('ids', $Ids)
                }
                if ($Filter) {
                        $uri.Add('filter', $Filter)
                }
                if ($Sort) {
                        $uri.Add('sort' , $Sort)
                }
                if ($Start) {
                        $uri.Add('start' , $Start)
                }
                if ($Limit) {
                        $uri.Add('limit' , $Limit)
                }
                if ($Token) {
                        $uri.Add('token' , $Token)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'GET' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Add-PfbNetworkInterface()
{
<#
.SYNOPSIS
        Adds Network Interfaces
.DESCRIPTION
        Helper function
        This function adds FlashBlade Network Interfaces
.EXAMPLE
        PS> Add-PfbNetworkInterface -Names 'rmme' -Attributes '{"address": "<IP>", "services": ["data"], "type": "vip"}'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                Address ( Mandatory)
                Services ( Mandatory)
                Type ( Mandatory)
                        
.OUTPUTS
        Network Interfaces response       
                
.NOTES
        Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/network-interfaces"; 
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbNetworkInterface()
{
<#
.SYNOPSIS
        Updates Network Interfaces
.DESCRIPTION
        Helper function
        This function updates FlashBlade Network Interfaces
.EXAMPLE
        PS> Update-PfbNetworkInterface -Names 'interface name' -Attributes '{"address": "<IP>", "services": ["data"], "type": "vip"}'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                Address (Mandatory)
                        
.OUTPUTS
        Network Interfaces response       
                
.NOTES
        Not Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

                $url = "/api/$ApiVers/network-interfaces";
                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }
                if ($Ids) {
                        $uri.Add('ids', $Ids)
                }

                $body = @{'address' = $Address}

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()

                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'PATCH' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Remove-PfbNetworkInterface()
{
<#
.SYNOPSIS
        Deletes Network Interfaces
.DESCRIPTION
        Helper function
        This function remvoes FlashBlade Network Interfaces
.EXAMPLE
        PS> Remove-PfbNetworkInterface -Names '<interface name>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        Address (Not Mandatory)
        Services (Not Mandatory)
        Type (Not Mandatory)
                        
.OUTPUTS
        Network Interfaces response       
                
.NOTES
        Not Tested                                 
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/network-interfaces";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbSmtp()
{
<#
.SYNOPSIS
        Lists all SMTP informatioon
.DESCRIPTION
        Helper function
        This function lists FlashBlade SMTP Information
.EXAMPLE
        PS> Get-PfbSmtp
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
                        
.OUTPUTS
        SMTP response       
                
.NOTES
        Tested                                         
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
        $url = "/api/$ApiVers/smtp";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbSmtp()
{
<#
.SYNOPSIS
        Modify SMTP server attributes.
.DESCRIPTION
        Helper function
        This function modifies FlashBlade SMTP Information
.EXAMPLE
        PS> Update-PfbSmtp -Attributes { "relay_host": "<Relay Host>" , "sender_domain": "<Sender Domain>"} '
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Attributes (Not Mandatory)
        InputFile (Not Mandatory)
                relay_host 
                sender_domain 
.OUTPUTS
        SMTP response       
                
.NOTES
        Not Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
)
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}


                $url = "/api/$ApiVers/smtp";
                $link = "https://$FlashBlade$url";
       		$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'PATCH' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Get-PfbSubnet()
{
<#
.SYNOPSIS
        Lists Array Subnet Configuration
.DESCRIPTION
        Helper function
        This function lists FlashBlade subnet configuration information
.EXAMPLE
        PS> Get-PfbSubnet 
        PS> Get-PfbSubnet -Names '<subnet name>'
        PS> Get-PfbSubnet -Filter 'Enabled="False"'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
                        
.OUTPUTS
        Subnets Response       
                
.NOTES
                                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
                $url = "/api/$ApiVers/subnets";
                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }
                if ($Ids) {
                        $uri.Add('ids', $Ids)
                }
                if ($Filter) {
                        $uri.Add('filter', $Filter)
                }
                if ($Sort) {$
                        Body.Add('sort' , $Sort)
                }
                if ($Start) {
                        $uri.Add('start' , $Start)
                }
                if ($Limit) {
                        $uri.Add('limit' , $Limit)
                }
                if ($Token) {
                        $uri.Add('token' , $Token)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'GET' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Add-PfbSubnet()
{
<#
.SYNOPSIS
        Create Array Subnet Configuration
.DESCRIPTION
        Helper function
        This function creates a FlashBlade subnet 
.EXAMPLE
        PS> Add-PfbSubnet -Names '<subnet name>' -Attributes ' { "enabled": "False" , "mtu": "1500"} '
        PS> Add-PfbSubnet -Names '<subnet name>' -InputFile '<file name>'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
        Attributes (Not Mandatory)
        InputFile (Not Mandatory)
                Enabled 
                Gateway 
                LAG 
                MTU 
                Prefix 
                Services 
                VLAN 
.OUTPUTS
        Subnets Response       
                
.NOTES
       Not Tested                         
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

                $url = "/api/$ApiVers/subnets";
                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'POST' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Update-PfbSubnet()
{
<#
.SYNOPSIS
        Update Array Subnet Configuration
.DESCRIPTION
        Helper function
        This function updates a FlashBlade subnet 
.EXAMPLE"
        PS> Update-PfbSubnet -Names '<subnet name>' -Attributes ' { "enabled": "False" , "mtu": "1500"} '
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
                        
.OUTPUTS
        Subnets Response       
                
.NOTES
        Not Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

                $url = "/api/$ApiVers/subnets";
                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'PATCH' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Remove-PfbSubnet()
{
<#
.SYNOPSIS
        Delete Array Subnets 
.DESCRIPTION
        Helper function
        This function removes a FlashBlade subnet 
.EXAMPLE"
        PS> Remove-PfbSubnet -Names '<subnet name>' 
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names () Mandatory)
                        
.OUTPUTS
        Subnets Response       
                
.NOTES
        Not Tested                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
                $url = "/api/$ApiVers/subnets";
                $link = "https://$FlashBlade$url";
                $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }

                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'DELETE' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Get-PfbObjectStoreAccessKey()
{
<#
.SYNOPSIS
        Lists all object store access keys.
.DESCRIPTION
        Helper function
        With no names parameter, lists all object store access keys. With the names parameter, lists the attributes for the specified object store access key.
.EXAMPLE
        PS> Get-PfbObjectStoreAccessKey

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Total_Only (Not Mandatory)
        
.OUTPUTS
        Object Store Access Key Response       
        created
        enabled
        name
        secret_access_key
        user
                id
                name
                total_physical
                resource_type
        
.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Total_Only 
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                        
                $url = "/api/$ApiVers/object-store-access-keys";
                $link = "https://$FlashBlade$url";
		$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

                if ($Names) {
                        $uri.Add('names', $Names)
                }
                if ($Ids) {
                        $uri.Add('ids', $Ids)
                }
                if ($Filter) {
                        $uri.Add('filter', $Filter)
                }
                if ($Sort) {
                        $uri.Add('sort' , $Sort)
                }
                if ($Start) {
                        $uri.Add('start' , $Start)
                }
                if ($Limit) {
                        $uri.Add('limit' , $Limit)
                }
                if ($Token) {
                        $uri.Add('token' , $Token)
                } 
		if ($Total_Only) {
                        $uri.Add('total_only' , $Total_Only)
                } 
                
                $request = [System.UriBuilder]$link
                $request.Query = $uri.ToString()
        
                $params = @{
                        SkipCertificateCheck = $skipcert
                        Method  = 'GET' 
                        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                        Uri = $request.Uri
                        Body = (ConvertTo-JSON $body) 
                        ContentType = 'application/json'       
                } 
                
                        if ($DEBUG) { write-host $request.Uri };
                        if ($DEBUG) { write-host @params };
                
                        try {
                                $obj = Invoke-RestMethod @params
                                $Items = $obj.items;
                                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                                Write-Host '---------------------------------------------------';
                                return $Items;
                        }
                        catch [System.Net.Http.HttpRequestException] {
                                $Request = $_.Exception
                                Write-host "Error trying to connect to $FlashBlade "
                                Get-InternalHTTPError;
                        }
                        catch {
                                $Request = $_.Exception
                                Write-host "Catchall Exception caught: $Request"
                                Get-InternalCatchAllError;
                        }
                        Finally { 
                                $Token = $(Get-InternalPfbAuthToken);
                                Get-InternalPfbAuthTokenLogout $Token;
                        }
}

function Add-PfbObjectStoreAccessKey()
{
<#
.SYNOPSIS
        Creates an object store access key.
.DESCRIPTION
        Helper function 
        This function Creates an object store access key.
.EXAMPLE
        PS> Add-PfbObjectStoreAccessKey -Name <<account/name of userto create key for>
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Name ( Mandatory)
                
.OUTPUTS
        Object Store Access Key Response       
        created
        enabled
        name
        secret_access_key
        user
                id
                name
                total_physical
                resource_type
                
.NOTES
        Tested
        Note: You can only have two Access Keys per user                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Name = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

	$body = @{
		'user' = @{ 
			'name'=$Name
		}
	}	
        
        $url = "/api/$ApiVers/object-store-access-keys";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Update-PfbObjectStoreAccessKey()
{
<#
.SYNOPSIS
        Modifies an object store access key.
.DESCRIPTION
        Helper function
        This function Modifies an object store access key.
.EXAMPLE
        Mark access key for enabled or disabled
        PS> Update-PfbObjectStoreAccessKey -Names 'name' -Attributes '{ "enabeld": "true" }'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Name ( Mandatory)
        Attributes ( Mandatory)
                
.OUTPUTS
        Object Store Access Key Response       
        created
        enabled
        name
        secret_access_key
        user
                id
                name
                total_physical
                resource_type
                
.NOTES
        Not Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/object-store-access-keys";        
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('name' , $Names)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbObjectStoreAccessKey()
{
<#
.SYNOPSIS
        Delete / Eradicate Object Store Access Keys
.DESCRIPTION
        Helper function
        This function deletes / eradicates Object Store Access Keys on the array after they have been destroyed 
.EXAMPLE
        PS> Remove-PfbObjectStoreAccessKey -Names 'name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                
.OUTPUTS
        Object Store Access Key Response          
        
.NOTES
        Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($Limit -gt 5)  { $Limit = 5;
        write-host "Limit set to max of 5 due to API policy";}
                
        $url = "/api/$ApiVers/object-store-access-keys";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }	
}

function Get-PfbObjectStoreAccount()
{
<#
.SYNOPSIS
        Lists all object store accounts
.DESCRIPTION
        Helper function
        With no names parameter, lists all object store accounts. With the names parameter, lists the attributes for the specified object store accounts
.EXAMPLE
        PS> Get-ObjectStoreAccount

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Total_Only (Not Mandatory)
        
.OUTPUTS
        Object Store Accounts       
        name
        user
                name
                id
                resource_type
        created
        enabled
        secret_access_key

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Total_Only 
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($Limit -gt 5)  { $Limit = 5; 
        write-host "Limit set to max of 5 due to API policy";}
                
        $url = "/api/$ApiVers/object-store-accounts";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        if ($Total_Only) {
                $uri.Add('total_only' , $Total_Only)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }	
}

function Add-PfbObjectStoreAccount()
{
<#
.SYNOPSIS
        Creates an object store account.
.DESCRIPTION
        Helper function 
        This function Creates an object store account
.EXAMPLE
        PS> Add-PfbObjectStoreAccessAccount -Names 'name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
                
.OUTPUTS
        Object Store Accounts       
        name
        user
                name
                id
                resource_type
        created
        enabled
        secret_access_key

                
.NOTES
        Not Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/object-store-accounts";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };

                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbObjectStoreAccount()
{
<#
.SYNOPSIS
        Delete / Eradicate Object Store Accounts
.DESCRIPTION
        Helper function
        This function deletes / eradicates Object Store Accounts on the array 
.EXAMPLE
        PS> Remove-PfbObjectStoreAccount -Names 'name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                
.OUTPUTS
        Object Store Accounts Response          
        
.NOTES
                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/object-store-accounts";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbObjectStoreUser()
{
<#
.SYNOPSIS
        Lists all object store users
.DESCRIPTION
        Helper function
        With no names parameter, lists all object store users. With the names parameter, lists the attributes for the specified object store accounts
.EXAMPLE
        PS> Get-PfbObjectStoreUser

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)
        Total_Only (Not Mandatory)
        
.OUTPUTS
        Object Store Accounts       
        name
        user
                name
                id
                resource_type
        created
        enabled
        secret_access_key

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit ,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start ,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Total_Only 
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($Limit -gt 5)  { $Limit = 5; 
        write-host "Limit set to max of 5 due to API policy";}
                
        $url = "/api/$ApiVers/object-store-users";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        if ($Total_Only) {
                $uri.Add('total_only' , $Total_Only)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }	
}

function Add-PfbObjectStoreUser()
{
<#
.SYNOPSIS
        Creates an object store user.
.DESCRIPTION
        Helper function 
        This function Creates an object store user
.EXAMPLE
        PS> Add-PfbObjectStoreUser -Names 'account/username'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
                
.OUTPUTS
        Object Store Accounts       
        name
        user
                name
                id
                resource_type
        created
        enabled
        secret_access_key

                
.NOTES
        Not Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/object-store-users";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        
        if ($Names) {
                $uri.Add('names', $Names)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Remove-PfbObjectStoreUser()
{
<#
.SYNOPSIS
        Delete / Eradicate Object Store User
.DESCRIPTION
        Helper function
        This function deletes / eradicates Object Store User from the array 
.EXAMPLE
        PS> Remove-PfbObjectStoreUser -Names 'account/username'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                
.OUTPUTS
        Object Store Accounts Response          
        
.NOTES
                                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/object-store-users";   
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }
}

function Get-PfbPolicies()
{
<#
.SYNOPSIS
        Lists all policies and their attributes.
.DESCRIPTION
        Helper function
         Lists all policies and their attributes.
        PS> Get-PfbPolicies

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
        IDs (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        Object Store Accounts       
        name
        user
                name
                id
                resource_type
        created
        enabled
        secret_access_key

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}
        
if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/policies";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 
        
                if ($DEBUG) { write-host $request.Uri };
                if ($DEBUG) { write-host @params };
        
                try {
                        $obj = Invoke-RestMethod @params
                        $Items = $obj.items;
                        Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                        Write-Host '---------------------------------------------------';
                        return $Items;
                }
                catch [System.Net.Http.HttpRequestException] {
                        $Request = $_.Exception
                        Write-host "Error trying to connect to $FlashBlade "
                        Get-InternalHTTPError;
                }
                catch {
                        $Request = $_.Exception
                        Write-host "Catchall Exception caught: $Request"
                        Get-InternalCatchAllError;
                }
                Finally { 
                        $Token = $(Get-InternalPfbAuthToken);
                        Get-InternalPfbAuthTokenLogout $Token;
                }	
}

function Add-PfbPolicies()
{
<#
.SYNOPSIS
        Create a snapshot scheduling policy with rule attributes. 
.DESCRIPTION
        Helper function 
        Create a snapshot scheduling policy with rule attributes. 
        Policies contain rules to capture file system snapshots for a set period of time and frequency, 
        including retaining of snapshots for a designated amount of time before being eradicated.
.EXAMPLE
        PS> Add-PfbPolicies -InputFile 'Filename'
        PS> Add-PfbPolicies -Names 'policy1' -Attributes  ' { "enabled":"True","rules":[{"at":"64800000","every":"1209600000","keep_for":"2000000000"}]} '
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
        At
        Enabled
        Every
        Keep_For
                
.OUTPUTS
        Policies
                
.NOTES
        Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);

if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/policies";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()


$params = @{
        SkipCertificateCheck = $skipcert
        Method  = 'POST' 
        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
        Uri = $request.Uri
        Body = (ConvertTo-JSON $body) 
        ContentType = 'application/json'       
} 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Update-PfbPolicies()
{
<#
.SYNOPSIS
        Updates a snapshot scheduling policy with rule attributes. 
.DESCRIPTION
        Helper function 
        Updates a snapshot scheduling policy with rule attributes. 
        Policies contain rules to capture file system snapshots for a set period of time and frequency, 
        including retaining of snapshots for a designated amount of time before being eradicated.
.EXAMPLE
        PS Update-PfbPolicies -Names 'policy1' -Attributes  ' { "enabled":"True","rules":[{"at":"64800000","every":"1209600000","keep_for":"2000000000"}]} '
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names ( Mandatory)
        Attributes (Not Mandatory)
        InputFile (Not Mandatory)
                
.OUTPUTS
        Policies
                
.NOTES
$body = @"
{
        "enabled": $Enabled,
        "rules": [
          {
            "at": $At,
            "every": $Every,
            "keep_for": $Keep_For
          } 
      ]
}
"@

        Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $Names = $null
);

if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}

        $url = "/api/$ApiVers/policies";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

$params = @{
        SkipCertificateCheck = $skipcert
        Method  = 'PATCH' 
        Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
        Uri = $request.Uri
        Body = (ConvertTo-JSON $body) 
        ContentType = 'application/json'       
} 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Remove-PfbPolicies()
{
<#
.SYNOPSIS
        Remove a policy
.DESCRIPTION
        Helper function
        This function deletes / eradicates a snapshot policy
.EXAMPLE
        PS> Remove-PfbPolcy -Names 'name'
        PS> Remove-PfbPolcy -IDs 'id'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Names (Not Mandatory)
                
.OUTPUTS
        Policy        
        
.NOTES
        Not Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}
        
if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/policies";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Get-PfbPoliciesFileSystem()
{
<#
.SYNOPSIS
        Lists all file systems mapped to a snapshot scheduling policy
.DESCRIPTION
        Helper function
        Lists all file systems mapped to a snapshot scheduling policy
.EXAMPLE
        PS> Get-PfbPoliciesFileSystem

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        MemberIDs (Not Mandatory)
        PolicyIDs (Not Mandatory)
        Member_Names (Not Mandatory)
        Policy_Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}
        
if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/policies/file-systems";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($MemberNames) {
                $uri.Add('member_names', $MemberNames)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids', $MemberIDs)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names', $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids', $Policy_ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Add-PfbPoliciesFileSystem()
{
<#
.SYNOPSIS
        Map a file system to a snapshot scheduling policy.
.DESCRIPTION
        Helper function 
        Map a file system to a snapshot scheduling policy.

.EXAMPLE
        PS> Add-PfbPoliciesFileSystem -MemberNames 'name' -PolicyNames 'policy name'
.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        MemberIDs (Not Mandatory)
        PolicyIDs (Not Mandatory)
        MemberNames (Not Mandatory)
        PolicyNames (Not Mandatory)
                
.OUTPUTS
        Policies         
        member
                id
                name
                resource
        policy
                id
                name
                resource

                
.NOTES
        Not Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null
);

if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/policies/file-systems";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($MemberNames) {
                $uri.Add('member_names', $MemberNames)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids', $MemberIDs)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names', $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids', $Policy_ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Remove-PfbPoliciesFileSystem()
{
<#
.SYNOPSIS
        Delete the mapping of a file system to a snapshot scheduling policy.
.DESCRIPTION
        Helper function
        This function Deletes the mapping of a file system to a snapshot scheduling policy.
.EXAMPLE
        PS> Remove-PfbPolicyFileSytem -Member_Names 'name' -Policy_Names 'name'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        MemberIDs (Not Mandatory)
        PolicyIDs (Not Mandatory)
        MemberNames (Not Mandatory)
        PolicyNames (Not Mandatory)
                
.OUTPUTS
        Policy        
        
.NOTES
        Tested                                
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
        $url = "/api/$ApiVers/policies/file-systems";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));
        
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($MemberNames) {
                $uri.Add('member_names', $MemberNames)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids', $MemberIDs)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names', $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids', $Policy_ids)
        }

        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Get-PfbPoliciesFileSystemSnapshot()
{
<#
.SYNOPSIS
        Lists all file systems snapshotts mapped to a snapshot scheduling policy
.DESCRIPTION
        Helper function
        Lists all file systems snapshots mapped to a snapshot scheduling policy
.EXAMPLE
        PS> Get-PfbPoliciesFileSystemSnapshot

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        MemberIDs (Not Mandatory)
        PolicyIDs (Not Mandatory)
        Member_Names (Not Mandatory)
        Policy_Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/policies/file-system-snapshots";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($MemberNames) {
                $uri.Add('member_names', $MemberNames)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids', $MemberIDs)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names', $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids', $Policy_ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Get-PfbPoliciesMember()
{
<#
.SYNOPSIS
        Lists all members, member types, and policies.
.DESCRIPTION
        Helper function
        Lists all members, member types, and policies.
.EXAMPLE
        PS> Get-PfbPoliciesMember

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        MemberIDs (Not Mandatory)
        PolicyIDs (Not Mandatory)
        Member_Names (Not Mandatory)
        Policy_Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $MemberIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $PolicyIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

        $url = "/api/$ApiVers/policies/members";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($MemberNames) {
                $uri.Add('member_names', $MemberNames)
        }
        if ($MemberIDs) {
                $uri.Add('member_ids', $MemberIDs)
        }
        if ($PolicyNames) {
                $uri.Add('policy_names', $PolicyNames)
        }
        if ($PolicyIDs) {
                $uri.Add('policyids', $Policy_ids)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Get-PfbQuotaGroup()
{
<#
.SYNOPSIS
        List groups with a hard limit quota, specified by a file system and either group names or IDs.
.DESCRIPTION
        Helper function
        List groups with a hard limit quota, specified by a file system and either group names or IDs.
.EXAMPLE
        PS> Get-PfbQuotaGroup -FileSystemName 'name of filesystem with quota enabled'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystemNames (Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Gids (Not Mandatory)
        GroupNames (Not Mandatory)
        Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        file_system
                id
                name
                resource_type
        file_system_default_quota
        group
                id
                name
        id
        name
        quota
        usage

.NOTES
        Get-PfbFileSystem -Filter 'hard_limit_enabled="true"'
        To get a file system that has a hard limit enabled
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GroupNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}
                
        $url = "/api/$ApiVers/quotas/groups";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($GIDs) {
                $uri.Add('gids', $GIDs)
        }
        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($GroupNames) {
                $uri.Add('group_names', $GroupNames)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()
      
        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }		
}

function Add-PfbQuotaGroup()
{
<#
.SYNOPSIS
        Create a hard limit quota for a group.
.DESCRIPTION
        Helper function
        Create a hard limit quota for a group.
.EXAMPLE
        PS> Add-PfbQuotaGroup

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        File_System_Names (Not Mandatory)
        Group_Names (Not Mandatory)
        Quota (Not Mandatory)
        Gids (Not Mandatory)
        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FileSystemName = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GroupName = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Quota = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

$body = " { 'quota': $Quota } " ;         

        $url = "/api/$ApiVers/quotas/groups";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemName) {
                $uri.Add('file_system_names', $FileSystemName)
        }
        if ($GIDs) {
                $uri.Add('gids', $GIDs)
        }
        if ($GroupName) {
                $uri.Add('group_names', $Group_Names)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Update-PfbQuotaGroup()
{
<#
.SYNOPSIS
        Modify a hard limit quota for a group.
.DESCRIPTION
        Helper function
        Modify a hard limit quota for a group.
.EXAMPLE
        PS> Update-PfbQuotaGroup

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystemNames (Not Mandatory)
        GroupNames (Not Mandatory)
        Quota (Not Mandatory)
        Gids (Not Mandatory)
        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GroupNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Quota = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}

$body = " { 'quota': $Quota } " ;         

        $url = "/api/$ApiVers/quotas/groups";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($GIDs) {
                $uri.Add('gids', $GIDs)
        }
        if ($GroupNames) {
                $uri.Add('group_names', $GroupNames)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Remove-PfbQuotaGroup()
{
<#
.SYNOPSIS
        Delete a hard limit quota for a group.
.DESCRIPTION
        Helper function
        Delete a hard limit quota for a group.
.EXAMPLE
        PS> Remove-PfbQuotaGroup -GID 'gid' -FileSystemNames 'name'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystemNames (Not Mandatory)
        GroupNames (Not Mandatory)
        Quota (Not Mandatory)
        Gids (Not Mandatory)
        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GroupName = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Quota = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}    

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

        $url = "/api/$ApiVers/quotas/groups";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($GIDs) {
                $uri.Add('gids', $GIDs)
        }
        if ($GroupNames) {
                $uri.Add('group_names', $GroupNames)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Get-PfbQuotaUser()
{
<#
.SYNOPSIS
        List users with a hard limit quota, specified by a file system and either user.
.DESCRIPTION
        Helper function
        List users with a hard limit quota, specified by a file system and either user.
.EXAMPLE
        PS> Get-PfbQuotaUser -FileSystemNames '<filesystem names>'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystemName (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Uids (Not Mandatory)
        UserNames (Not Mandatory)
        Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        file_system
                id
                name
                resource_type
        file_system_default_quota
        User
                id
                name
        id
        name
        quota
        usage

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UserNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}
        
if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

        $url = "/api/$ApiVers/quotas/users";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($UIDs) {
                $uri.Add('uids', $UIDs)
        }
        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($UserNames) {
                $uri.Add('user_names', $UserNames)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Add-PfbQuotaUser()
{
<#
.SYNOPSIS
        Create a hard limit quota for a user.
.DESCRIPTION
        Helper function
        Create a hard limit quota for a user.
.EXAMPLE
        PS> Add-PfbQuotaUser -FileSystemNames '<filesystem names>'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystemNames (Not Mandatory)
        UserNames (Not Mandatory)
        Quota (Not Mandatory)
        Uids (Not Mandatory)
        
.OUTPUTS
        file_system
                id
                name
                resource_type
        file_system_default_quota
        User
                id
                name
        id
        name
        quota
        usage

.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UserNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Quota = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

$body = " { 'quota': $Quota } " ;

        $url = "/api/$ApiVers/quotas/users";
        $headers = @{};
        $headers.Add("x-auth-token", $(Get-InternalPfbAuthToken));

        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($UIDs) {
                $uri.Add('uids', $UIDs)
        }
        if ($UserNames) {
                $uri.Add('user_names', $UserNames)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'POST' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Update-PfbQuotaUser()
{
<#
.SYNOPSIS
        Modify a hard limit quota for a user.
.DESCRIPTION
        Helper function
        Modify a hard limit quota for a user.
.EXAMPLE
        PS> Update-PfbQuotaUser

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        File_System_Names (Not Mandatory)
        User_Names (Not Mandatory)
        Quota (Not Mandatory)
        Uids (Not Mandatory)
        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UserNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Quota = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

$body = " { 'quota': $Quota } " ;

        $url = "/api/$ApiVers/quotas/users";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($UIDs) {
                $uri.Add('uids', $UIDs)
        }
        if ($UserNames) {
                $uri.Add('user_names', $UserNames)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
        }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Remove-PfbQuotaUser()
{
<#
.SYNOPSIS
        Delete a hard limit quota for a user.
.DESCRIPTION
        Helper function
        Delete a hard limit quota for a user.
.EXAMPLE
        PS> Remove-PfbQuotasUser -UID 'uid' -FileSystemName 'name'

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        File_System_Names (Not Mandatory)
        User_Names (Not Mandatory)
        Quota (Not Mandatory)
        Uids (Not Mandatory)
        
.OUTPUTS
        Policies      
        member
                id
                name
                resource_type
        policy
                id
                name
                resource_type

.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FileSystemName = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UserNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Quota = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}          

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

        $url = "/api/$ApiVers/quotas/users";
        $link = "https://$FlashBlade$url";
        $uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemName) {
                $uri.Add('file_system_names', $FileSystemName)
        }
        if ($UIDs) {
                $uri.Add('uids', $UIDs)
        }
        if ($UserNames) {
                $uri.Add('user_names', $UserNames)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Get-PfbUsageGroup()
{
<#
.SYNOPSIS
        Lists all groups with a hard limit quota or any amount of space usage.
.DESCRIPTION
        Helper function
        Lists all groups with a hard limit quota or any amount of space usage.
.Example
        PS> Get-PfbUsageGroup

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystemNames ( Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Gids (Not Mandatory)
        Group_Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        file_system
                id
                name
                resource_type
        file_system_default_quota
        group
                id
                name
        id
        name
        quota
        usage

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GroupNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $GIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

$url = "/api/$ApiVers/usage/groups";
$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($GIDs) {
                $uri.Add('gids', $GIDs)
        }
        if ($GroupNames) {
                $uri.Add('group_names', $GroupNames)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Get-PfbUsageUser()
{
<#
.SYNOPSIS
        Lists all users with a hard limit quota or any amount of space usage.
.DESCRIPTION
        Helper function
        Lists all users with a hard limit quota or any amount of space usage.
.EXAMPL
        PS> Get-PfbUsageUsers

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        FileSystemNames ( Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Uids (Not Mandatory)
        UserNames (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        file_system
                id
                name
                resource_type
        file_system_default_quota
        User
                id
                name
        id
        name
        quota
        usage

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$TRUE)][ValidateNotNullOrEmpty()][string] $FileSystemNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UserNames = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $UIDs = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 
        
$url = "/api/$ApiVers/usage/users";
$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($FileSystemNames) {
                $uri.Add('file_system_names', $FileSystemNames)
        }
        if ($UIDs) {
                $uri.Add('uids', $UIDs)
        }
        if ($UserNames) {
                $uri.Add('user_names', $UserNames)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Get-PfbAdmin()
{
<#
.SYNOPSIS
        Lists all admins and their API tokens.
.DESCRIPTION
        Helper function
        Lists all admins and their API tokens.
.EXAMPLE
        PS> Get-PfbAdmin
        PS> Get-PfbAdmin -Expose 1

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Expose (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Ids (Not Mandatory)
        Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        file_system
                id
                name
                resource_type
        file_system_default_quota
        User
                id
                name
        id
        name
        quota
        usage

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Expose ,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 
                
$url = "/api/$ApiVers/admins";
$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Expose) {
                $uri.Add('expose', $Expose)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

function Update-PfbAdmin()
{
<#
.SYNOPSIS
        Modify admin API token attributes.
.DESCRIPTION
        Helper function
        Modify admin API token attributes.
.EXAMPLE
        PS> Update-PfbAdmin

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Admin (Not Mandatory)
        Api_Token_Timeout (Not Mandatory)
        Create_Api_Token (Not Mandatory)
        IDs (Not Mandatory)
        Names (Not Mandatory)
        Old_Password (Not Mandatory)
        Password (Not Mandatory)
        Delete_Api_Token (Not Mandatory)

        
.OUTPUTS
        Admins
        api_token
                created
                expired
                token
        id
        name

.NOTES
        Not Tested                     
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Admin = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $ApiTokenTimout = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $CreateApiToken ,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][booleab] $DeleteApiToken ,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][securestring] $OldPassword = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][securestring] $Password = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
                
$url = "/api/$ApiVers/admins";
$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Admins) {
                $uri.Add('admins', $Admins)
        }
      
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'PATCH' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Get-PfbAdminCache()
{
<#
.SYNOPSIS
        List role privileges for each directory service administrator.
.DESCRIPTION
        Helper function
        List role privileges for each directory service administrator.
.EXAMPLE
        PS> Get-PfbAdminCache

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Regresh (Not Mandatory)
        Filter (Not Mandatory)
        Limit (Not Mandatory)
        Ids (Not Mandatory)
        Names (Not Mandatory)
        Sort (Not Mandatory)
        Start (Not Mandatory)
        Token (Not Mandatory)

        
.OUTPUTS
        admins/cache
        id
        name
        role
        time

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Limit = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Refresh = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][int32] $Start = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Token = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

$url = "/api/$ApiVers/admins/cache";
$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        if ($Expose) {
                $uri.Add('expose', $Expose)
        }
        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($Start) {
                $uri.Add('start' , $Start)
        }
        if ($Limit) {
                $uri.Add('limit' , $Limit)
        }
        if ($Token) {
                $uri.Add('token' , $Token)
        } 
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Remove-PfbAdminCache()
{
<#
.SYNOPSIS
        Deletes the users cached role.
.DESCRIPTION
        Helper function
        Deletes the users cached role.
.EXAMPLE
        PS> Remove-PfbAdminCache

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Ids (Not Mandatory)
        Names (Not Mandatory)

.OUTPUTS
        admins/cache

.NOTES
        Not Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Names = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Ids = $null
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

$url = "/api/$ApiVers/admins/cache";
$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Names) {
                $uri.Add('names', $Names)
        }
        if ($Ids) {
                $uri.Add('ids', $Ids)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'DELETE' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Get-PfbSupport()
{
<#
.SYNOPSIS
        Lists or tests the attribute settings of the Phone Home and Remote Assistance facility.
.DESCRIPTION
        Helper function
        Lists the attribute settings of the Phone Home and Remote Assistance facility.
        List the network connection test results of the Phone Home and Remote Assistance facilities on the FlashBlade array.
.EXAMPLE
        PS> Get-PfbSupport
        PS> Get-PfbSupport -Test 1 -TestType 'phonehome'
        PS> Get-PfbSupport -Test 1 -TestType 'remote-assist' 

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Test (Not Mandatory)
        Filter (Not Mandatory)
        Sort (Not Mandatory)
        TestType (Not Mandatory)
        
.OUTPUTS
        list output
        name
        phonehome_enabled
        proxy
        remote_assist_active
        remote_assist_expires
        remote_assist_opened
        remote_assist_paths
                component_name
                status
        remote_assist_status

        test output
        component_addres
        component_name
        description
        destination
        enabled
        resource
        result_details
        success
        test_type

.NOTES
        Tested                        
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Filter = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Sort = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $TestType = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][boolean] $Test
);
if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
} 

if ($Test) {
        $url = "/api/$ApiVers/support/test";
} Else {
        $url = "/api/$ApiVers/support";
}

$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Filter) {
                $uri.Add('filter', $Filter)
        }
        if ($Sort) {
                $uri.Add('sort' , $Sort)
        }
        if ($TestType) {
                $uri.Add('test_type' , $TestType)
        }
        
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()

        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'GET' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }	
}

function Update-PfbSupport()
{
<#
.SYNOPSIS
        Modify the attributes of the Phone Home and Remote Assistance facility on the FlashBlade array.
.DESCRIPTION
        Helper function
        Modify the attributes of the Phone Home and Remote Assistance facility on the FlashBlade array.
.EXAMPLE
        PS> Update-PfbSupport -InputFile '<filename>'
        PS> Update-PfbSupport -Attributes ' {"remote_assist_active":true}'
        PS> Update-PfbSupport -Attributes '{ "phonehome_enabled": true, "proxy": "https://proxy.example.com:8080", "remote_assist_active": true } '

.INPUTS
        FlashBlade (Not Mandatory)
        APIToken (Not Mandatory)
        Attributes (Not Mandatory)
        InputFile (Not Mandatory)
        
        phonehome_enabled (boolean)
        proxy (string)
        remote_assist_active (boolean) 

.OUTPUTS
        support
        remote_assist_active
        remote_assist_expires
        remote_assist_opened
        remote_assist_paths
                component_name
                status
        remote_assist_status

.NOTES
        Tested                       
#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $FlashBlade = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $ApiToken =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $SkipCertificateCheck =$null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $InputFile = $null,
  [Parameter(Mandatory=$FALSE)][ValidateNotNullOrEmpty()][string] $Attributes = $null
);

if (!$FlashBlade) {
        $myreturn = $(Get-InternalPfbJson);
        $FlashBlade = $myreturn[0]
        $ApiToken = $myreturn[1]
        $ApiVers = $myreturn[2]
        $SkipCertificateCheck = $myreturn[3]
}

if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues=@("Invoke-RestMethod:SkipCertificateCheck",$true)
        if ($DEBUG) {write-host "Skipping the Certificate Check $SkipCertificateCheck"}
        $skipcert=$True
}      

if ($InputFile) { 
        $body = Get-Content -Raw $InputFile | out-string | ConvertFrom-Json -AsHashtable;
}        else {
        $body = (ConvertFrom-Json $Attributes -AsHashtable);
}
                
$url = "/api/$ApiVers/support";
$link = "https://$FlashBlade$url";
$uri = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
  
        $request = [System.UriBuilder]$link
        $request.Query = $uri.ToString()
               
        $params = @{
                SkipCertificateCheck = $skipcert
                Method  = 'Patch' 
                Headers = @{ 'x-auth-token' = $(Get-InternalPfbAuthToken)} 
                Uri = $request.Uri
                Body = (ConvertTo-JSON $body) 
                ContentType = 'application/json'       
        } 

        if ($DEBUG) { write-host $request.Uri };
        if ($DEBUG) { write-host @params };

        try {
                $obj = Invoke-RestMethod @params
                $Items = $obj.items;
                Write-Host ("Running function: {0} " -f $MyInvocation.MyCommand);
                Write-Host '---------------------------------------------------';
                return $Items;
        }
        catch [System.Net.Http.HttpRequestException] {
                $Request = $_.Exception
                Write-host "Error trying to connect to $FlashBlade "
                Get-InternalHTTPError;
                }
        catch {
                $Request = $_.Exception
                Write-host "Catchall Exception caught: $Request"
                Get-InternalCatchAllError;
        }
        Finally { 
                $Token = $(Get-InternalPfbAuthToken);
                Get-InternalPfbAuthTokenLogout $Token;
        }
}

#==================================================================================================================

Export-ModuleMember -Function Get-Pfb* -Alias *
Export-ModuleMember -Function Add-Pfb* -Alias *
Export-ModuleMember -Function Update-Pfb* -Alias *
Export-ModuleMember -Function Remove-Pfb* -Alias *