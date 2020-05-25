# WinCertes - Use Cases

Below are some examples regarding WinCertes command lines in typical environments. These command lines should be launched in cmd.exe with administrative rights.

> **WARNING:** when you test, remember to always add "-s https://acme-staging-v02.api.letsencrypt.org/directory" to the command line.

> **NOTE:** feedback is welcome! Please file a bug if some of the following needs fixing, or if you want to add another example.

IIS Enrollment - case 1
-----------------------

In this example, IIS is used to serve both HTTP and HTTPS, so we use IIS for the enrollment, and bind the resulting certificate to IIS Default Web Site.
The IIS website files resides in c:\inetpub\wwwroot.

```dos
WinCertes -e me@example.com -d www.test.example.com -d test.example.com -w=c:\inetpub\wwwroot -b "Default Web Site" -p
```

IIS Enrollment - case 2
-----------------------

In this example, we enroll IIS but IIS is not serving web pages through HTTP (port 80), so we use WinCertes for HTTP validation instead.

```dos
WinCertes -e me@example.com -d www.test.example.com -d test.example.com -a -b "Default Web Site" -p
```

Apache Enrollment
-----------------

In this example, Apache is not serving web pages through HTTP, so we use WinCertes for HTTP validation.

We assume Apache is installed in C:\Program Files\Apache Group\Apache2 , and the certificate and private key are respectively in conf\server.crt and conf\server.key

First of all, we need to put a PowerShell script in c:\ProgramData\WinCertes\Apache.ps1 with the content:

```PowerShell
Param(
                [Parameter(Mandatory=$True,Position=1)]
                [string]$pfx,
                [Parameter(Mandatory=$True)]
                [string]$pfxPassword,
                [Parameter(Mandatory=$True)]
                [string]$cer,
                [Parameter(Mandatory=$True)]
                [string]$key
                )

# Copy certificate: here's an example for Apache
Copy-Item -Path $cer -Destination C:\\Program\ Files\\Apache\ Group\\Apache2\\conf\\server.crt
Copy-Item -Path $key -Destination C:\\Program\ Files\\Apache\ Group\\Apache2\\conf\\server.key
& 'C:\Program Files\Apache Group\Apache2\bin\httpd.exe -k restart'
```

Then we can launch the following command:

```dos
WinCertes -e me@example.com -d www.test.example.com -d test.example.com -a -f c:\ProgramData\WinCertes\Apache.ps1 -p
```

> **Note:** This script can be adapted to work with Tomcat using APR.

Tomcat Enrollment
-----------------

In this example, Tomcat is not serving web pages through HTTP, so we use WinCertes for HTTP validation.

We assume Tomcat is installed in C:\Program Files\Tomcat, please adapt the following to you actual installation paths.

First of all, we need to put a PowerShell script in c:\ProgramData\WinCertes\Tomcat.ps1 with the content:

```PowerShell
Param(
                [Parameter(Mandatory=$True,Position=1)]
                [string]$pfx,
                [Parameter(Mandatory=$True)]
                [string]$pfxPassword,
                [Parameter(Mandatory=$True)]
                [string]$cer,
                [Parameter(Mandatory=$True)]
                [string]$key
                )

# Copy certificate: here's an example for Apache
Copy-Item -Path $pfx -Destination C:\\Program\ Files\\Tomcat\\etc\\certificate.p12
(Get-Content C:\\Program\ Files\\Tomcat\\conf\\server.xml) `
	-replace 'keystorePass="(\w+)"', 'keystorePass="$pfxPassword"' |
	Out-File C:\\Program\ Files\\Tomcat\\conf\\server.xml
& 'C:\Program Files\Tomcat\bin\catalina.bat stop'
& 'C:\Program Files\Tomcat\bin\catalina.bat start'
```

Then we can launch the following command:

```dos
WinCertes -e me@example.com -d www.test.example.com -d test.example.com -a -f c:\ProgramData\WinCertes\Tomcat.ps1 -p
```

> **Note:** in the above example, we assume that the connector configuration in the server.xml contains the following:
```xml
<Connector ...
	keyStoreType="PKCS12"
	keyStoreFile="C:\Program Files\Tomcat\etc\certificate.p12"
	keystorePass="changeit" 
	... />
```