# Box Name:
BRUTUS - Easy Sherlock
# Scenario:
"In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution."
# Provided artifacts:
- **Brutus.zip**
  - **Auth.log**
    - _This is a log file that tracks authentication mechanisms. Including User auth, sudo, and ssh._
  - **WTMP.bin**
    - _WTMP(write temp) is a binary file for user logins and out. Similar to UTMP(current logins) and BTMP(bad logins)_
  - **UTMP.py**
    - _Provided python script to translate the binary file into human readable like the last command in linux_
# Initial Analysis:
1. I used 7zip to unzip Brutus.zip to examine its contents.
# Questions:
[comment]: <> (Q/A from the fields)
