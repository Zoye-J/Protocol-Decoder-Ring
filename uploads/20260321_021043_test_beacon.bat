@echo off
echo Starting test...
ping 93.184.216.34 -n 8 -w 1000
ping 8.8.8.8 -n 4 -w 1000
nslookup example.com
nslookup github.com
nslookup google.com
echo Done.