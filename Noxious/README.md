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
9269	68.440010	172.17.79.135	172.17.79.136	LLMNR	55850	86	Standard query response 0xe708 A DCC01 A 172.17.79.135
```
2.  _What is the hostname of the rogue machine?_
    - To find the host name my first thought was to look for any DHCP traffic coming from 172.17.79.135. So I applied this filter ```ip.src == 172.17.79.135 && dhcp``` and there is only instances. A discovery ```Host Name: V17VT3M03``` and a request ```Host Name: kali``` both from 172.17.79.135.
```
1666	11.510185	172.17.79.135	255.255.255.255	DHCP	67	311	DHCP Discover - Transaction ID 0xa7ea9ba0
12714	635.466361	172.17.79.135	172.17.79.254	DHCP	67	324	DHCP Request  - Transaction ID 0x481fced6
```
3.  _{{question}}_
    - {{answer w/ thoughts}} 
```
{{Example of data}}
```
4.  _{{question}}_
    - {{answer w/ thoughts}} 
```
{{Example of data}}
```
5.  _{{question}}_
    - {{answer w/ thoughts}} 
```
{{Example of data}}
```
6.  _{{question}}_
    - {{answer w/ thoughts}} 
```
{{Example of data}}
```
7.  _{{question}}_
    - {{answer w/ thoughts}} 
```
{{Example of data}}
```
8.  _{{question}}_
    - {{answer w/ thoughts}} 
```
{{Example of data}}
```

