*** Settings ***
Library  ./RoboNmap.py
Library  Collections

*** Variables ***
${TARGET}     127.0.0.1

*** Test Cases ***
Run Basic Port Scan
    Nmap Default Scan  ${TARGET}
    nmap print results

Run Full TCP Scan
    Nmap All Tcp Scan  ${TARGET}
    nmap print results

Run Specific UDP Scan on port 53
    Nmap Specific Udp Scan  ${TARGET}  53
    nmap print results

Run Specific TCP Scan on port 80
    Nmap Specific Tcp Scan  ${TARGET}  80
    nmap print results

Run Service Discovery Scan
    Nmap Os Services Scan  ${TARGET}
    nmap print results