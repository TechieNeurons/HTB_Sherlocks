# OpTinselTrace 4

## Speech
```
Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128
```

## Analysis

## Questions
1. The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?
    - 172.17.79.133
2. Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?
    - 9100
3. What is the full name of printer running on the server?
    - Northpole HP LaserJet 4200n
4. Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?
    - Douglas Price
5. The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?
    - The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion.
6. What was the name of the scheduled print job?
    - MerryChristmas+BonusAnnouncment
7. Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?
    - /Administration/securitykeys/ssh_systems/id_rsa
8. What is size of this file in bytes?
    - 1914
9. What was the hostname of the other compromised critical server?
    - christmas.gifts
10. When did the Grinch attempt to delete a file from the printer? (UTC)
    - 2023-12-08 12:18:14