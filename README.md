# flashblade-powershell-toolkit
Windows PowerShell Module for Pure Storage FlashBlade

NOTE:
For management and consistency this repo now ONLY resides on the PowerShellGallery
https://www.powershellgallery.com/packages/PureFBModule/


Client for Purity//FB REST API, developed by Pure Storage, Inc. Documentations can be found at purity-fb.readthedocs.io.

For more information, please visit http://www.purestorage.com

Requirements.
PowerShell 6.0

Installation & Usage

Using the REST API consists of the following steps:
1. Generate the API token. This is a one-time step.
2. Create the REST session, using the API token and capturing the returned x-auth-token. 
3. Submit REST API requests, using the x-auth-token.
4. Invalidate the REST session.

The session is valid until it is ended or experiences 30 minutes of inactivity.
Every cmdlet in the module will log out of its session after its process completes.

Each REST API request is comprised of a complete URL. The complete URL used to make a Purity//FB REST request includes the following components:
Method (GET, POST, PUT, PATCH, or DELETE) Purity array
REST API version
URI

Each function begins with Get-Pfb, Add-Pfb, Update-Pfb or Remove-Pfb
e.g. Get-PfbFileSystems

This version can be called either with a json control file called FlashBlade.JSON, 
or by parsing -FlashBlade 'FQDN or IP' -APIToken 'FB Token'

The control file holds :
1. The FQDN or IP of the FlashBlade.
2. The API Token of the user processing the commands.
3. The version of the API that you wish to call.
4. Whether you wish to skip validating your Certificates

Note: From version 1.10 the APIVers paramater needs speechmarks in the JSON file, previously this was not required.

[
	{
		"FlashBlade": 	"xxx.xxx.xxx.x",
		"APIToken": 	"xxx",
		"APIvers": 	"1.10",
		"SkipCertificateCheck": "True"
	}
]


Only API function not available at this point is ability to download logs. 
Will work on that.
