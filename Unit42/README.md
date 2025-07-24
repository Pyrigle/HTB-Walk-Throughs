# Box Name:
Unit42 - Easy Sherlock
# Scenario:
&nbsp; &nbsp; "In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows  system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign."
# Provided artifacts:
- **unit42.zip**
  - **Microsoft-Windows-Sysmon-Operational.evtx**
    - We were provided a Sysmon Event log that we can open with event viewer. 
# Initial Analysis:
&nbsp; &nbsp; The event log contained 169 events with 14 unique Event IDs.
The 169 events only spanned a couple of minutes. The first thing I did was group by event and take a look for anything that immediately stood out. The first thing that stood out was a process created by CyberJunkie -```C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe"```. Quickly searching through the rest of the events for related logs pertaining to preventivo24 based off other high interest IDs like 3, 22, 11, and 23, I was able to glean rather quickly that the preventivo24 malware was installed, attempted to obfuscate itself, and then later made connection to a suspicious IP, suggesting potential C2 or exfiltration. 
<details>
  
<summary>Event IDs:</summary>
  
    - 1: Process Creation
    - 2: File Creation Time Changed
    - 3: Network Connection
    - 5: Process Terminated
    - 7: Image Loaded
    - 10: Process Access
    - 11: File Created
    - 12: Registery Object Added or Deleted
    - 13: Registery Value Set
    - 15 File Create Stream Hash
    - 17: Pipe Created
    - 22: DNS Query
    - 23: File Delete Logged
    - 26: File Delete Detected
</details>

- _Prior to viewing the logs I had to check Unit42.zip hash via ```Get-FileHash "${pwd}\unit42.zip -Algorithm SHA1"``` and unzipped the file using 7ZIP_

# Questions:
1. _How many Event logs are there with Event ID 11?_
    - There was 56. This was simple to just Group By Event ID which then shows you how many of each event there is. 

2. _Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?_
    - Again we already had everything grouped by Event ID. There was only 6 Event ID: 1's. They mostly looked normal except for ```"C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe" ```.
```
technique_id=T1204,technique_name=User Execution
2024-02-14 03:41:56.538
EV_RenderedValue_2.00
10672
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
1.1.2
Photo and vn Installer
Photo and vn
Photo and Fax Vn
Fattura 2 2024.exe
"C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe" 
C:\Users\CyberJunkie\Downloads\
DESKTOP-887GK2L\CyberJunkie
EV_RenderedValue_13.00
1814183
1
```
3. _Which Cloud drive was used to distribute the malware?_
    - The very first entry in the event logs is an Event ID: 22 which correlates to a DNS query. This DNS query was to dropboxusercontent.com and was subsequently followed by sveral Event ID: 11 one of which was Preventivo24.
```
2024-02-14 03:41:25.269
EV_RenderedValue_2.00
4292
uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com
0
type:  5 edge-block-www-env.dropbox-dns.com;::ffff:162.125.81.15;198.51.44.6;2620:4d:4000:6259:7:6:0:1;198.51.45.6;2a00:edc0:6259:7:6::2;198.51.44.70;2620:4d:4000:6259:7:6:0:3;198.51.45.70;2a00:edc0:6259:7:6::4;
C:\Program Files\Mozilla Firefox\firefox.exe
DESKTOP-887GK2L\CyberJunkie
```
4. _For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?_
    - Timestomping gets picked up under Event ID: 2. There was only 16 instances of Event ID: 2. I was able to flip through the files pretty quickly and find then the pdf was altered ```"2024-01-14 08:10:06.029"```
```
technique_id=T1070.006,technique_name=Timestomp
2024-02-14 03:41:58.404
EV_RenderedValue_2.00
10672
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\TempFolder\~.pdf
2024-01-14 08:10:06.029
2024-02-14 03:41:58.404
DESKTOP-887GK2L\CyberJunkie
```
5. _The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename._
    - This is another step sorting by group helps pretty quickly. File creations are Event ID: 11 and once.cmd was created pretty early in the logs so we are able to find it fairly quickly. ```"C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\cmmc.cmd"``` Alternatively you could just search the log file for once.cmd as there is not than many instances of it. 
```
2024-02-14 03:41:58.404
EV_RenderedValue_2.00
10672
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\cmmc.cmd
2024-02-14 03:41:58.404
DESKTOP-887GK2L\CyberJunkie

```
6. _The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?_
    - Event ID: 22 covers DNS queries. So the malliocus file would generate one if it tries to test its connection at all. There was only 3 Event ID: 22 so it was pretty easy to find ```"example.com"```.
```
2024-02-14 03:41:56.955
EV_RenderedValue_2.00
10672
www.example.com
0
::ffff:93.184.216.34;199.43.135.53;2001:500:8f::53;199.43.133.53;2001:500:8d::53;
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
DESKTOP-887GK2L\CyberJunkie
``` 
7. _Which IP address did the malicious process try to reach out to?_
    - In the logs we were provided there was only a singular network connection made Event ID: 3 ```"93.184.216.34"```.
```
technique_id=T1036,technique_name=Masquerading
2024-02-14 03:41:57.159
EV_RenderedValue_2.00
10672
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
DESKTOP-887GK2L\CyberJunkie
tcp
True
False
172.17.79.132
-
61177
-
False
93.184.216.34
-
80
-
```
8. _The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?_
    - Event ID: 5 is process terminated. This was the only event 5 in the logs provided. The time stamp was ```"2024-02-14 03:41:58.795"``` 
```
2024-02-14 03:41:58.795
EV_RenderedValue_2.00
10672
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
DESKTOP-887GK2L\CyberJunkie
```

