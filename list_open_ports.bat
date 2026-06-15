@echo off
title Open Ports Viewer (TCP/UDP)
color 0A

:: Define the output file path on the desktop
set "OutputFile=%USERPROFILE%\Desktop\Open_Ports_List.txt"

:: Use a single > to create/overwrite the file with the first line
echo ============================================================ > "%OutputFile%"
:: Use >> to append all subsequent lines to the same file
echo                 ACTIVE OPEN PORTS (TCP ^& UDP) >> "%OutputFile%"
echo ============================================================ >> "%OutputFile%"
echo. >> "%OutputFile%"

echo [ --- TCP LISTENING PORTS --- ] >> "%OutputFile%"
echo   Proto  Local Address          Foreign Address        State           PID >> "%OutputFile%"
echo ---------------------------------------------------------------------------- >> "%OutputFile%"
netstat -anop tcp | find /i "LISTENING" >> "%OutputFile%"
echo. >> "%OutputFile%"

echo [ --- UDP ACTIVE PORTS --- ] >> "%OutputFile%"
echo   Proto  Local Address          Foreign Address        State           PID >> "%OutputFile%"
echo ---------------------------------------------------------------------------- >> "%OutputFile%"
netstat -anop udp | find /i "udp" >> "%OutputFile%"
echo. >> "%OutputFile%"

:: Display the generated file on the screen
type "%OutputFile%"

:: Print a confirmation message
echo ============================================================
echo SUCCESS: Report has been saved to your Desktop as: 
echo Open_Ports_List.txt
echo ============================================================
echo Press any key to exit...
pause >nul