@echo off

ECHO:
ECHO THIS COMMAND FILE IS UNDER DEVELOPMENT. IT WAS DRAFTED AFTER QUICKLY
ECHO hacking aloopkin\WinCertes
ECHO:
ECHO Since then cshawky\WinCertes is finished to beta release and supports
ECHO an unlimited number of unique certificates, with Registry Store.
ECHO I have not tested any of the DNS challenges or IIS WebRoot. I assume
ECHO they will work unmodified.
ECHO:
ECHO The aim is to create a wrapper script around WinCertes.exe and Perform
ECHO necessary steps BEFORE and AFTER running WinCertes.
ECHO The wrapper script runs as a scheduled task.
ECHO
ECHO In my case, it means:
ECHO	- Enable allow HTTP ports in firewall
ECHO	- Run WinCertes update (my version creates all the PEMs needed)
ECHO	- Enable Block local HTTP ports in firewall
ECHO	- Stop hMailServer
ECHO	- install certificate pair
ECHO	- Start hMailServer
ECHO	- Stop VisualSVN server1
ECHO	- Install single certificate
ECHO	- Start VisualSVN server1
ECHO:
ECHO TODO:	Update to match cshawky\WinCertes, write new wrapper for hMailServer, svn
ECHO
PAUSE
EXIT

REM -------------------------------------------------------------------------------
REM
REM Example Batch file for controlling WinCertes
REM It is assumed that WinCertes is installed to C:\Program Files\WinCertes
REM
SET UPDATEDATE=2/Apr/2020
SET VERSION=1.0.0
SET AUTHOR=CSHAWKY
REM
REM -------------------------------------------------------------------------------
	REM Force directory to script folder
	setlocal ENABLEEXTENSIONS
	setlocal ENABLEDELAYEDEXPANSION
	REM Current working directory
	SET BASEPATH=%~dp0
	cd /d %BASEPATH%

	IF IF "%1"=="HELP" GOTO :HELP
	GOTO :MAIN

REM -------------------------------------------------------------------------------
:HELP
	ECHO Create or manage a certificate using WinCertes
	ECHO:
	ECHO Command:   CreateCertificate.cmd {Option}
	ECHO:
	ECHO {Option} being one of:
	ECHO     null	Create or update the certificate using the specified parameters
	ECHO	REVOKE	Revoke the certificate using stored parameters in registry
	ECHO	UPDATE	Create/Update a certificate using stored parameters in registry
	ECHO	script	Run the Powershell script (normally for testing the script)
	ECHO:
	PAUSE
	GOTO :DONE
REM -------------------------------------------------------------------------------
:MAIN
	REM Installation path for WinCertes.exe
	REM SET INSTALL=C:\Program Files\WinCertes
	SET INSTALL=..\WinCertes
	SET WINCERTES=%INSTALL%\WinCertes.exe

	SET TEST=
	REM Comment out the next line to disable test mode
	SET TEST=-s https://acme-staging-v02.api.letsencrypt.org/directory

	REM Comment out EMAIL, SCRIPT if you do not with to use defaults.
	REM Replace domain names and certificate name below with your choices.
	REM CERTNAME, DOMAINS are mandatory parameters for creating the certificate
	REM CERTNAME is recommended if updating an existing certificate (information pulled from registry)
	REM If CERTNAME is omitted, the first domain name will be used.
	SET EMAIL=-e testing@gmail.com
	SET DOMAINS=-d server1.mydomain.com -d server2.mydomain.com -d mail.mydomain.com -d svn.mydomain.com
	SET CERTNAME=-n server1.mydomain.com
	SET SCRIPTFILE=%BASEPATH%\ManageCertificate.ps1
	SET SCRIPT=
	IF EXIST "%SCRIPTFILE%" SET SCRIPT=-f "%SCRIPTFILE%"

	IF "%1"=="REVOKE" (
		ECHO Revoking Certificate...
		"%WINCERTES%" -r 4 -n %CERTNAME%
		GOTO :DONE
	) ELSE IF "%1"=="UPDATE" (
		ECHO Performing Certificate update using last saved primary configuration...
		"%WINCERTES%"
	) ELSE IF "%1"=="SCRIPT" (
		IF NOT EXIST "%SCRIPTFILE%" (
			ECHO ERROR: "%SCRIPTFILE%" does not exist. Exiting...
			GOTO :DONE
		)
		SET PfxFileName=!CERTFILENAME!
		FOR /F "usebackq tokens=3*" %%A IN (`REG QUERY "HKLM\Software\WinCertes" /v PfxFileName`) DO (set PfxFileName=%%A)
		FOR /F "usebackq tokens=3*" %%A IN (`REG QUERY "HKLM\Software\WinCertes" /v PfxPassword`) DO (set PfxPassword=%%A)
		ECHO Existing ComputerRole = %PfxPassword%
		POWERSHELL.EXE -NoProfile -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -File !SCRIPTFILE! -pfx !PfxFileName! -pfxPassword !PfxPassword!
	) ELSE(
		ECHO Creating or update the Certificate with the specified parameters...
		"%WINCERTES%" -a -x !TEST! !EMAIL! !DOMAINS! !CERTNAME! !SCRIPT!
	)

REM -------------------------------------------------------------------------------
:DONE
PAUSE