# Eset
Eset Smart Security...

* 1.Code->Download Zip
* 2.Unpack
* 3.Install

* Block Port UP/DOWN - TCP/UDP:
```bash
20-25,1900,42,81,101,158,67-70,5353,137-139,445,7,1,2,3,4,5,6,8,9,10,8118,9040,9050,5037-5038,5001,8883,107,111,512,513,544,556,1745,5678,9535,3702,2504,2701-2704,33060,8080,3000,
9,11,12,13,14,15,16,17,18,19,37,39,43,88,102,109,110,113,117,118,119,143,150,156,161,170,179,194,213,322,349,389,464,507,514,515,517,518,520,522,525,526,529,530,531,532,533,540,
543,546,547,548,550,554,560,561,563,565,568,569,593,612,613,636,666,691,749,750,800,989,990,992,993,994,995,1109,1110,1155,1034,1167,1270,1478,1512,1524,1607,1701,
1711,1723,1731,1755,1801,1812,1813,1863,1944,2053,2106,2177,2234,2460,2525,2725,2869,3020,3074,3126,3132,3268,3269,3343,3540,3544,3587,3776,3847,3882,3935,4350,
5357,5358,5679,5720,6073,9753,47624,
40000-65535,123,1433,1434,1477,3389,3535,2049,500,4500,135,162,10010,7680,5040,5050,3306,5426,5355,1980,9009,1337,13333,13344,5985,2382,2383,2393,2394,11320,53
```
* Incomming Block - All
* Disable All allow connections (config ESET) and Enable Port 53 UDP local and remote - process svchost.exe
* For some programs, you need to deactivate the Eset firewall and use the program. 
* Then activate the firewall again. In most cases everything works normally.
* Activate program 30 day: https://t2bot.ru/en/esetkeys/
