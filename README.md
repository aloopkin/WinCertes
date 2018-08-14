# WinCertes - ACME Client for Windows

WinCertes is a simple ACMEv2 Client for Windows, able to manage the automatic issuance and renewal of SSL Certificates, for IIS or other web servers. It is based on [Certes](https://github.com/fszlin/certes) Library

![GPLv3 License](https://www.gnu.org/graphics/license-logos-by-christian-candena-cc-by.png)

Requirements:
- Windows Server 2008 R2 SP1 or higher (.Net 4.6.1 or higher), 64-bit

Features:
- CLI-based for easy integration with DevOps
- Easy certificate requests & automated SSL bindings
- Auto renewal using Scheduled Task
- SAN support (multi-domain certificates)
- Support for v2 of the Let's Encrypt API including Wildcard Certificate support (*.example.com)
- Optional powershell scripting for advanced deployment (Exchange, multi-server, etc)
- Http only challenge validation.
	- Built-in Http Challenge Server for easier configuration of challenge responses
	- Ability to support already installed web server (by default IIS) to provide challenge responses
- Import of certificate and key into chosen CSP/KSP, enabling compatibility with HSMs
- Support of any ACMEv2 compliant CA, including Let's Encrypt and Let's Encrypt Staging (for tests/dry-run)
- Windows Installer for easy deployment
- Configuration is stored in Registry
- Support for certificate revocation
- Logs activity to STDOUT and file

----------
Quick Start (IIS users)
----------
1. Download from GitHub and install it.
2. Launch a command line (cmd.exe) as Administrator
3. Enter the following command:
```DOS
WinCertes.exe -e me@example.com -d test1.example.com -d test2.example.com -b "Default Web Site" -p
```
And... That's all! The certificate is requested from Let's Encrypt, and bound to IIS' Default Web Site

Advanced users can explore the different validation modes, deployment modes and other advanced options.

Development & Bug Reporting
-------------

If you have a bug or feature and you can fix the problem yourself please just:

   1. File a new issue
   2. Fork the repository
   2. Make your changes 
   3. Submit a pull request, detailing the problem being solved and testing steps/evidence
   
If you cannot provide a fix for the problem yourself, please file an issue and describe the fault with steps to reproduce.

The development requires Visual Studio 2017, and Wix if you want to build the installer.

Command Line Options
-------------

```DOS
WinCertes.exe:
  -s, --service=VALUE        the ACME Service URI to be used (optional,
                               defaults to Let's Encrypt)
  -e, --email=VALUE          the account email to be used for ACME requests (
                               optional, defaults to no email)
  -d, --domain=VALUE         the domain(s) to enroll (mandatory) *
  -w, --webroot=VALUE        the web server root directory (optional, defaults
                               to c:\inetpub\wwwroot)
  -p, --periodic             should WinCertes create the Windows Scheduler task
                               to handle certificate renewal (default=no) *
  -b, --bindname=VALUE       IIS site name to bind the certificate to, e.g. "
                               Default Web Site".
  -f, --scriptfile=VALUE     PowerShell Script file e.g. "C:\Temp\script.ps1"
                               to execute upon successful enrollment (default=
                               none)
  -a, --standalone           should WinCertes create its own WebServer for
                               validation (default=no). WARNING: it will use
                               port 80
  -c, --cleanup              should WinCertes clean up the generated PFX right
                               before exiting (default=no when using scriptfile,
                                yes otherwise).
  -r, --revoke               should WinCertes revoke the certificate identified
                               by its domains (incompatible with other
                               parameters except -d)
  -k, --csp=VALUE            import the certificate into specified csp. By
                               default WinCertes imports in the default CSP.

*: these paremeters are not stored into configuration.

Typical usage: WinCertes.exe -e me@example.com -d test1.example.com -d test2.example.com -p
This will automatically create and register account with email me@example.com, and
request the certificate for test1.example.com and test2.example.com, then import it into
Windows Certificate store (machine context), and finally set a Scheduled Task to manage renewal.

"WinCertes.exe -d test1.example.com -d test2.example.com -r" will revoke that certificate.
```

Using Non-Let's Encrypt CA
-------------

By default, WinCertes uses Let's Encrypt (LE) CA to issue SSL certificates. However there are several cases in which one would like to use another CA:
1. You're testing the certificate deployment for LE: add `-s https://acme-staging-v02.api.letsencrypt.org/directory` to the command line
2. You want to use another public CA: add `-s https://public-ca-acmev2.example.com` to the command line
3. You want to use an internal ACMEv2 compliant CA: deploy the internal CA certificates to the Windows Trusted CA store, and add `-s https://internal-ca-acmev2.example.corp` to the command line



This project is (c) 2018 Alexandre Aufrere
Released under the terms of GPLv3
https://evertrust.fr/