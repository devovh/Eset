# Eset
Eset Smart Security...

* 1.Code->Download Zip
* 2.Unpack
* 3.Install

* Block Port UP/DOWN - TCP/UDP:
```bash
20-25,1900,67-68,5353,137-139,445,7,1,8118,9040,9050,5037-5038,5001,8883,107,111,512,513,544,556,1745,5678,9535,3702,
40000-65535,123,500,4500,135,162,10010,7680,5040,5050,3306,5426,5355,1980,9009,1337,13333,13344,5985,0
```
* Incomming Block - All
* Disable All allow connections (config ESET) and Enable Port 53 UDP local and remote - process svchost.exe
* For some programs, you need to deactivate the Eset firewall and use the program. 
* Then activate the firewall again. In most cases everything works normally.
* Activate program 30 day: https://t2bot.ru/en/esetkeys/
