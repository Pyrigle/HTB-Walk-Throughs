# Box Name:
Noxious - Very Easy
# Scenario:
&nbsp; &nbsp; "The IDS device alerted us to a possible rogue device in the internal Active Directory network. The Intrusion Detection System also indicated signs of LLMNR traffic, which is unusual. It is suspected that an LLMNR poisoning attack occurred. The LLMNR traffic was directed towards Forela-WKstn002, which has the IP address 172.17.79.136. A limited packet capture from the surrounding time is provided to you, our Network Forensics expert. Since this occurred in the Active Directory VLAN, it is suggested that we perform network threat hunting with the Active Directory attack vector in mind, specifically focusing on LLMNR poisoning."
# Provided artifacts:
**noxious.zip**
  - **Capture.pcap**
    - This contained about 25k packets of traffic that can be opened in wireshark for analysis.
# Initial Analysis:
&nbsp; &nbsp; The first thing I did upon opening the PCAP was to add the column for port. The scenario mentioned LLMNR poisoning, and that the traffic was directed towards 172.17.79.136. LLMNR is Link Local Multicast Name Resolution which is essentially failover DNS. This means its likely that there was a failed DNS look up at some point and the LLMNR traffic from 172.17.79.136 was intercepted and tampered with. So the first filter I added to the PCAP was ```LLMNR || NTLM``` to view LLMNR traffic and any potentially associated NTLM traffic. This revealed a User Name on Forela-WKstn002, the workstation answering, and several other key details. 

- _Prior to viewing the logs I had to check noxious.zip hash via ```Get-FileHash "${pwd}\noxious.zip -Algorithm SHA1 "``` and unzipped the file using 7ZIP_

# Questions:
1. _Its suspected by the security team that there was a rogue device in Forela's internal network running responder tool to perform an LLMNR Poisoning attack. Please find the malicious IP Address of the machine._
    - When looking at the LLMNR traffic there is one host responding 172.17.79.135
```
Reference Packet(s):
9269	68.440010	172.17.79.135	172.17.79.136	LLMNR	55850	86	Standard query response 0xe708 A DCC01 A 172.17.79.135
```
2.  _What is the hostname of the rogue machine?_
    - To find the host name my first thought was to look for any DHCP traffic coming from 172.17.79.135. So I applied this filter ```ip.src == 172.17.79.135 && dhcp``` and there is only instances. A discovery ```Host Name: V17VT3M03``` and a request ```Host Name: kali``` both from 172.17.79.135.
```
Reference Packet(s):
1666	11.510185	172.17.79.135	255.255.255.255	DHCP	67	311	DHCP Discover - Transaction ID 0xa7ea9ba0
12714	635.466361	172.17.79.135	172.17.79.254	DHCP	67	324	DHCP Request  - Transaction ID 0x481fced6
```
3.  _Now we need to confirm whether the attacker captured the user's hash and it is crackable!! What is the username whose hash was captured?_
    - We were able to see a username super early when filtered the PCAP by: ```llmnr || ntlmssp```. The name was john.deacon.

```
Reference Packet(s):
9508	78.320628	fe80::7994:1860:711:c243	fe80::2068:fe84:5fc8:efb7	SMB2	445	717	Session Setup Request, NTLMSSP_AUTH, User: FORELA\john.deacon
```
4.  _In NTLM traffic we can see that the victim credentials were relayed multiple times to the attacker's machine. When were the hashes captured the First time?_
    - Through our same search above we were able to see the first time creds were relayed. ```UTC Arrival Time: Jun 24, 2024 11:18:30.922052000 UTC```

```
Reference Packet(s):
9292	68.459907	fe80::7994:1860:711:c243	fe80::2068:fe84:5fc8:efb7	SMB2	445	717	Session Setup Request, NTLMSSP_AUTH, User: FORELA\john.deacon
```
5.  _What was the typo made by the victim when navigating to the file share that caused his credentials to be leaked?_
    - Since LLMNR is a failover we needed to find the initial failed DNS query. To do this we can add a filter for ```dns```. There was 6 failed look ups for ```DCC01```.
```
Reference Packet(s):
9242	68.195453	172.17.79.4	172.17.79.136	DNS	50439	142	Standard query response 0xf088 No such name A DCC01.forela.local SOA dc01.forela.local
9254	68.430165	172.17.79.2	172.17.79.4	DNS	49601	1081	Standard query response 0x0d72 No such name A DCC01.localdomain SOA a.root-servers.net RRSIG NSEC locker RRSIG NSEC aaa RRSIG OPT
9255	68.431184	172.17.79.4	172.17.79.136	DNS	54957	152	Standard query response 0x5cef No such name A DCC01.localdomain SOA a.root-servers.net
9460	76.235259	172.17.79.4	172.17.79.136	DNS	50775	142	Standard query response 0xbd72 No such name A DCC01.forela.local SOA dc01.forela.local
9482	78.295496	172.17.79.2	172.17.79.4	DNS	53350	1081	Standard query response 0xa798 No such name A DCC01.localdomain SOA a.root-servers.net RRSIG NSEC aaa RRSIG NSEC locker RRSIG OPT
9483	78.298350	172.17.79.4	172.17.79.136	DNS	60292	152	Standard query response 0x022d No such name A DCC01.localdomain SOA a.root-servers.net
```
6.  _To get the actual credentials of the victim user we need to stitch together multiple values from the ntlm negotiation packets. What is the NTLM server challenge value?_
    - Here we need to consult back to the trio of packets from earlier. You can see one of the three is a NTLMSSP_CHALLENGE. Within this packet we can see ```NTLM Server Challenge: 30fe22d567d06435```
```
Reference Packet(s):
9319	68.490152	fe80::2068:fe84:5fc8:efb7	fe80::7994:1860:711:c243	SMB2	51926	412	Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE
```
7.  _Now doing something similar find the NTProofStr value._
    - For this portion we need the NTProofStr which is provided in the authentication packet. ```NTProofStr: 82f4436bed0e4cf0580702f59eb34df1```
```
Reference Packet(s):
9320	68.490854	fe80::7994:1860:711:c243	fe80::2068:fe84:5fc8:efb7	SMB2	445	717	Session Setup Request, NTLMSSP_AUTH, User: FORELA\john.deacon
```
8.  _To test the password complexity, try recovering the password from the information found from packet capture. This is a crucial step as this way we can find whether the attacker was able to crack this and how quickly._
    - For this step I cheated a little bit as I did not have any word lists to test this on. THe format for cracking an NTLM hash is ```username::domain:server_challenge:ntproofstr:blob```.
We have all of these parts already so we just need to get the blob which is the NTLMv2 response without the NTProofStr ```NTLMv2 Response[…]:82f4436bed0e4cf0580702f59eb34df1010100000000000080e4d59406c6da0176dcad34579d163600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100```. So all together we end up with ```john.deacon::FORELA:30fe22d567d06435:82f4436bed0e4cf0580702f59eb34df1:010100000000000080e4d59406c6da0176dcad34579d163600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100```. Once I assembled the parts I checked the write up for the correct password, then created a password.txt file with ```NotMyPassword0K?``` in it. From hashcat we just need to enter ```.\hashcat.exe -a 0 -m5600 .\NTLMHash.txt .\Password.txt```. In hashcat a 0 is for a dictionary attack and -m 5600 is NTLMv2.
