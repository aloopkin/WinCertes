# WinCertes - Registry Settings

Advanced configuration of WinCertes can be perfomed using Registry settings. These settings are located in `HKLM\SOFTWARE\WinCertes`

cshawky\WinCertes also supports creation of the registry keys from the command line without further processing. e.g.: 
```dos
    WinCertes --creatednskeys --certname mail.mydomain.com
```
The parameters may also be entered on the command line like:
```dos
  -n, --certname=VALUE       Unique Certificate name excluding file extension  
                               e.g. "wincertes.com" (default=first domain name)
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
```
All parameters are saved to the registry under `HKLM\SOFTWARE\WinCertes\{certname}`

General Settings
-------------
Some settings are configured automatically using the command line, and thus won't be detailed here. Only additional settings are mentioned

- renewalDays: DWORD, decimal, number of days before certificate expiration when WinCertes should trigger the renewal


DNS "acme-dns" validation plugin
-------------

See https://github.com/joohoi/acme-dns for more information on acme-dns. All the paramaters are "String" parameters.

- DNSValidatorType: acme-dns
- DNSServerURL: The acme-dns server "update" URL, e.g. http://acme-dns.host/update
- DNSServerUser: The acme-dns username, e.g. eabcdb41-d89f-4580-826f-3e62e9755ef2 
- DNSServerKey: The acme-dns password, e.g. pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0
- DNSServerSubDomain: The acme-dns subdomain, e.g. d420c923-bbd7-4056-ab64-c3ca54c9b3cf


DNS "Windows DNS" validation plugin
-------------

This plugin allows to update Windows DNS server records. All the parameters are "String" parameters.

- DNSValidatorType: win-dns
- DNSServerHost: The Windows DNS Server Hostname/IP, e.g. dns.example.corp
- DNSServerUser:  The Windows DNS Server User, with enough rights on the server to update DNS contents, e.g. Administrator
- DNSServerPassword: The password of the aformentioned Windows DNS Server User
- DNSServerZone: The DNS Zone in which are the hosts to be validated, and as declared in the Windows DNS Server, e.g. example.corp
