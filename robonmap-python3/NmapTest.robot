*** Settings ***
Library  RoboNmap
Library  Collections

*** Variables ***
${TARGET} =  google.com

*** Test Cases ***
Run Basic Port Scan
    Nmap Script Scan  ${TARGET}  file_export=nmap.txt  script_name=ssl-enum-ciphers  portlist=443
    ${TLS} =  Get TLS ciphers
	Log  ${TLS}