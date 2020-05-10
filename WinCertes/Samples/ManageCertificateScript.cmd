@echo off
REM -------------------------------------------------------------------------------
REM
SET APP=Powershell wrapper sscript
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

	CALL CreateCertificate.cmd SCRIPT

REM -------------------------------------------------------------------------------
:DONE
	PAUSE