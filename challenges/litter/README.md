# Litter

## Speech
```
Khalid has just logged onto a host that he and his team use as a testing host for many different purposes. It’s off their corporate network but has access to lots of resources on the network. The host is used as a dumping ground for a lot of people at the company, but it’s very useful, so no one has raised any issues. Little does Khalid know; the machine has been compromised and company information that should not have been on there has now been stolen – it’s up to you to figure out what has happened and what data has been taken.
```

## Analysis

## Questions
1. At a glance, what protocol seems to be suspect in this attack?
    > DNS
2. There seems to be a lot of traffic between our host and another, what is the IP address of the suspect host?
    > 192.168.157.145
3. What is the first command the attacker sends to the client?
    > whoami
4. What is the version of the DNS tunneling tool the attacker is using?
    > 0.07
5. The attackers attempts to rename the tool they accidentally left on the clients host. What do they name it to?
    > win_installer.exe
6. The attacker attempts to enumerate the users cloud storage. How many files do they locate in their cloud storage directory?
    > 0
7. What is the full location of the PII file that was stolen?
    > C:\users\test\documents\client data optimisation\user details.csv
8. Exactly how many customer PII records were stolen?
    > 721