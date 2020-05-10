# WinCertes - ACME Client for Windows

WinCertes is a simple ACMEv2 Client for Windows, able to manage the automatic issuance and renewal of SSL Certificates, for IIS or other web servers. It is based on [Certes](https://github.com/fszlin/certes) Library and [Certes](https://github.com/aloopkin/WinCertes). Pre-compiled binaries are available from GitHub (just look for the standard GitHub menu entry).

![GPLv3 License](https://www.gnu.org/graphics/gplv3-88x31.png)

- cshawky\WinCertes updates:
    - All registry details now stored under a subkey
    - Support for information in the root key (but prefer user moves the values into the named subkey)
    - Support for "extra" subkey
    - Legacy support of aloopkin\WinCertes registry setup has had limited testing.
    - Huge changes to the options and registry interface (to support unlimited certificates and legacy support).
    - Registry create rewritten and tested as creation of HKLM\Software\WinCertes kept failing on Win10 and Win2016 with UAC, Antivirus, Malware Bytes and Acronis Active Protection all enabled.
    - More diagnostic debugging added, but could not get NLog loglevel change to take effect so added command line check before initialising logs. New parameter --debug to increase debug without recompilation.
    - Lots of testing of --certname -d -x -a --reset --show --creatednskeys -l -e -f
    - Added built in support to create PEM type certificates --exportpem
        - Private Key PEM
        - Full Certificate PEM with private key (e.g. VisualSVN Server)
        - Separate Certificate PEM without private key (e.g. hMailServer)
        - PFX for IIS unchanged, still need IIS certificate to revoke it (why have not researched)
    - Added support for password entry
    - Added attempt for Elevation if not run as administrator or UAC active
    - All certificate files stored in a folder = Environment.CurrentDirectory + "\\Certificates"
    - Assumes WinCertes.exe is installed to C:\Program Files\WinCertes or CWD.
    - Certificate path is stored in registry but not yet read at startup. Once supported this would allow each set of certificates to be written to a different folder. The folder should have restricted access due to the potential existence of the private RSA key text file.
    - Tested on Windows 10, Windows 2016
    - TODO Ensure this readme matches the new code
    - TODO Get github community to confirm IIS, DNS registration features work
    - TODO .\Samples\ scripts were drafted late, not tested before all of the changes above. Update and simplify scripts. Add scheduled task script to the mix that includes example for start/stop of IIS, Firewall rules, hMailServer and VisualSVN.

Requirements:
- Windows Server 2008 R2 SP1 or higher (.Net 4.6.1 or higher), 64-bit

Features:
- CLI-based for easy integration with DevOps
- Easy certificate requests & automated SSL bindings
- Auto renewal using Scheduled Task
- SAN support (multi-domain certificates)
- Full support for ACMEv2, including Wildcard Certificate support (\*.example.com) [\*]
- Optional powershell scripting for advanced deployment (Exchange, multi-server, etc)
- HTTP challenge validation.
	- Built-in Http Challenge Server for easier configuration of challenge responses
	- Ability to support already installed web server (by default IIS) to provide challenge responses
- DNS challenge validation
	- Support for Windows DNS Server
	- Support for [acme-dns](https://github.com/joohoi/acme-dns)
- Import of certificate and key into chosen CSP/KSP, enabling compatibility with HSMs
- Support of any ACMEv2 compliant CA, including Let's Encrypt and Let's Encrypt Staging (for tests/dry-run)
- Windows Installer for easy deployment
- Configuration is stored in Registry
- Support for certificate revocation
- Logs activity to STDOUT and file

[\*] Warning: Let's Encrypt does not allow wildcard certificates issuance with HTTP validation. So, the DNS validation mode MUST be used to retrieve wildcard certificate.

[EverTrust](https://github.com/EverTrust)

----------
Quick Start (IIS users)
----------
1. Download from GitHub and install it.
2. Launch a command line (cmd.exe) as Administrator
3. Enter the following command:
```dos
WinCertes.exe -e me@example.com -d test1.example.com -d test2.example.com -w -b "Default Web Site" -p
```
And... That's all! The certificate is requested from Let's Encrypt, and bound to IIS' Default Web Site

Advanced users can explore the different validation modes, deployment modes and other advanced options. See [Registry Settings](./Registry.md) regarding advanced options and DNS validation modes.

Command Line Options
-------------

```dos
WinCertes.exe:
  -n, --certname=VALUE       Unique Certificate name excluding file extension  
                               e.g. "wincertes.com" (default=first domain name)
  -s, --service=VALUE        ACME Service URI to be used (optional, defaults to
                               Let's Encrypt)
  -e, --email=VALUE          Account email to be used for ACME requests  (
                               optional, defaults to no email)
  -d, --domain=VALUE         Domain(s) to enroll (mandatory)
  -w, --webserver[=ROOT]     Toggles the local web server use and sets its ROOT
                               directory (default c:\inetpub\wwwroot).
                               Activates HTTP validation mode.
  -p, --periodic             Should WinCertes create the Windows Scheduler task
                               to handle certificate renewal (default=no)
  -b, --bindname=VALUE       IIS site name to bind the certificate to,       e.
                               g. "Default Web Site". Defaults to no binding.
  -f, --scriptfile=VALUE     PowerShell Script file e.g. "C:\Temp\script.ps1"
                               to execute upon successful enrollment (default=
                               none)
  -x, --exportcerts          Should WinCertes export the certificates including
                               PEM format.
  -a, --standalone           Activate WinCertes internal WebServer for
                               validation. Activates HTTP validation mode.
                               WARNING: it will use port 80 unless -l is
                               specified.
  -r, --revoke[=REASON]      Should WinCertes revoke the certificate identified
                               by its domains (to be used only with -d or -n).
                               REASON is an optional integer between 0 and 5.
  -k, --csp=VALUE            Import the certificate into specified csp. By
                               default WinCertes imports in the default CSP.
  -t, --renewal=N            Trigger certificate renewal N days before
                               expiration, default 30
  -l, --listenport=N         Listen on port N in standalone mode (for use with -
                               a switch, default 80)
      --dnscreatekeys        Create all DNS values in the registry and exit.
                               Use with --certname. Manually edit registry or
                               include on command line
      --dnstype=VALUE        DNS Validator type: acme-dns, win-dns
      --dnsurl=VALUE         DNS Server URL: http://blah.net
      --dnshost=VALUE        DNS Server Host
      --dnsuser=VALUE        DNS Server Username
      --dnspassword=VALUE    DNS Server Password
      --dnskey=VALUE         DNS Server Account Key
      --dnssubdomain=VALUE   DNS Server SubDomain
      --dnszone=VALUE        DNS Server Zone
      --debug                Enable extra debug logging
      --extra                Deprecated: Manages certificate name "extra".
                               Please use -n instead
      --no-csp               Disable import of the certificate into CSP. Use
                               with caution, at your own risk. REVOCATION WILL
                               NOT WORK IN THAT MODE.
      --password=VALUE       Certificate password min 16 characters (default=
                               random)
      --reset                Reset all configuration parameters for --certname
                               and exit
      --show                 Show current configuration parameters and exit


Typical usage:

  "WinCertes.exe -a -e me@example.com -d test1.example.com -d test2.example.com -p"

This will automatically create and register account with email me@example.com, and
request the certificate for (test1.example.com, test2.example.com), then import it
into Windows Certificate store, create a Scheduled Task to manage renewal, then save
settings to registry [HKLM\SOFTWARE\WinCertes\test1.example.com]. Once the settings
are saved to registry WinCertes.exe may be run with -n test1.example.com to re-use
the same settings. e.g.

  "WinCertes.exe -n test1.example.com" will renew that certificate.
  "WinCertes.exe -n test1.example.com -r" will revoke that certificate.

Be sure to revoke a certificate before deleting registry keys via --reset

  "WinCertes.exe -n test1.example.com --reset" will revoke that certificate.

For debugging use: -s https://acme-staging-v02.api.letsencrypt.org/directory

```

Using Non-Let's Encrypt CA
-------------

By default, WinCertes uses Let's Encrypt (LE) CA to issue SSL certificates. However there are several cases in which one would like to use another CA:
1. You're testing the certificate deployment for LE: add `-s https://acme-staging-v02.api.letsencrypt.org/directory` to the command line
2. You want to use another public CA: add `-s https://public-ca-acmev2.example.com` to the command line
3. You want to use an internal ACMEv2 compliant CA: deploy the internal CA certificates to the Windows Trusted CA store, and add `-s https://internal-ca-acmev2.example.corp` to the command line. If you need a solution to give ACMEv2 capabilities to your internal PKI, you can check e.g. [EverTrust TAP](https://evertrust.fr/en/tap.html).

About PowerShell Scripting
-------------

WinCertes gives the option to launch a PowerShell script upon successfull enrollment. This script will receive two parameters:
- pfx: contains the full path to the PFX (PKCS#12) file
- pfwPassword: contains the password required to parse the PFX

The PFX can then be parsed using e.g. [Get-PfxData](https://docs.microsoft.com/en-us/powershell/module/pkiclient/get-pfxdata), and later on 
re-exported with different pasword, or imported within a different Windows store.

The following code is a simple example of PowerShell script that you can call from WinCertes:
```PowerShell
Param(
                [Parameter(Mandatory=$True,Position=1)]
                [string]$pfx,
                [Parameter(Mandatory=$True)]
                [string]$pfxPassword
                )

# Build the pfx object using file path and password
$mypwd = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
$mypfx = Get-PfxData -FilePath $pfx -Password $mypwd

# Start the real work. Here we simply append the certificate DN to a text file
$mypfx.EndEntityCertificates.Subject | Out-File -FilePath c:\temp\test.txt -Append
```

About IIS Configuration
-------------

WinCertes can auto-configure IIS regarding the SSL certificate and its bindings. However, IIS configuration needs to be modified in order for 
WinCertes HTTP validation to work: WinCertes requires the "*" mimetype to be set, else IIS will refuse to serve the challenge file.
WinCertes tries to do this automatically as well, but it might fail depending on your version and setup of IIS.

It is possible to fix the issue permanently:
- using the IIS Management Console, in the "MIME Types" section
- or by adding/modifying the web.config file at the document root of IIS, with the following content:

```XML
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap fileExtension=".*" mimeType="application/octet-stream" />
            <mimeMap fileExtension="." mimeType="application/octet-stream" />
        </staticContent>
    </system.webServer>
</configuration>
```

Troubleshooting
-------------

Usually when the enrollment fails you can get more information in the latest error message given by WinCertes. Most of the time it should look like:
```
Failed to register and validate order with CA: Could not validate challenge: Could not resolve DNS name test.example.com
```
Most common causes are:
- When using the "standalone" mode (`-a` switch), the Windows Firewall gets in the way. Try to fully deactivate it.
- When not using the "standalone" mode, the Web Server document root is not specified correctly: use the `-w` switch.
- You made too many tests on the LE production server. Remember to add `-s https://acme-staging-v02.api.letsencrypt.org/directory` to the command line when you test the enrollment!
- After testing you need to reinitialize WinCertes context: delete all registry keys under HKLM\Software\WinCertes


Development & Bug Reporting
-------------

If you have a bug or feature and you can fix the problem yourself please just:

   1. File a new issue
   2. Fork the repository
   2. Make your changes 
   3. Submit a pull request, detailing the problem being solved and testing steps/evidence
   
If you cannot provide a fix for the problem yourself, please file an issue and describe the fault with steps to reproduce.

The development requires Visual Studio 2017 or 2019, and Wix if you want to build the installer.



This project is (c) 2018-2019 Alexandre Aufrere

Released under the terms of GPLv3

https://evertrust.fr/
