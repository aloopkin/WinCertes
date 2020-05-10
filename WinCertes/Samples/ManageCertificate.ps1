Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$pfx,
    [Parameter(Mandatory=$True)]
    [string]$pfxPassword
    )

"Processing the certificate $pfx $pfxPassword"

# Build the pfx object using file path and password
#$mypwd = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
#$mypfx = Get-PfxData -FilePath $pfx -Password $mypwd

#$pfxPassword > CertificateData.pwd

# Start the real work. Here we simply append the certificate DN to a text file
#$mypfx.EndEntityCertificates.Subject | Out-File -FilePath CertificateData.txt

#$NewPwd = ConvertTo-SecureString -String "86253339Shawcross*65Matthew*08"

#Export-PfxCertificate -PfxData $mypfx -FilePath CertificateData.pfx -Password $NewPwd -Force -ProtectTo "BIGBIRD\xshawky","THETARDIS\shawky"

# Export current registry
REG EXPORT HKLM\Software\WinCertes Certificates\CertificateData.reg

#openssl pkcs12 -in $pfx -passin $pfxPassword -out CertificateData.pem