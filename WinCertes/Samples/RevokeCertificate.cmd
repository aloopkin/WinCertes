@echo off
REM -------------------------------------------------------------------------------
REM
SET UPDATEDATE=2/Apr/2020
SET VERSION=1.0.0
SET AUTHOR=SHAWKY
REM
REM -------------------------------------------------------------------------------
	REM Force directory to script folder
	setlocal ENABLEEXTENSIONS
	setlocal ENABLEDELAYEDEXPANSION
	SET BASEPATH=%~dp0
	cd /d %BASEPATH%

	CALL CreateCertificate.cmd REVOKE

REM -------------------------------------------------------------------------------
:DONE
PAUSE