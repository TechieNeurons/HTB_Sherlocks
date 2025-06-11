# NeuroSync-D

#API #linux #logs #access.log

##
> NeuroSync™ is a leading suite of products focusing on developing cutting edge medical BCI devices, designed by the Korosaki Coorporaton. Recently, an APT group targeted them and was able to infiltrate their infrastructure and is now moving laterally to compromise more systems. It appears that they have even managed to hijack a large number of online devices by exploiting an N-day vulnerability. Your task is to find out how they were able to compromise the infrastructure and understand how to secure it.

## Questions
1. What version of Next.js is the application using?
    > 
    - 
2. What local port is the Next.js-based application running on?
    > 
    - 
3. A critical Next.js vulnerability was released in March 2025, and this version appears to be affected. What is the CVE identifier for this vulnerability?
    > 
    - 
4. The attacker tried to enumerate some static files that are typically available in the Next.js framework, most likely to retrieve its version. What is the first file he could get?
    > 
    - 
5. Then the attacker appears to have found an endpoint that is potentially affected by the previously identified vulnerability. What is that endpoint?
    > 
    - 
6. How many requests to this endpoint have resulted in an "Unauthorized" response?
    > 
    - 
7. When is a successful response received from the vulnerable endpoint, meaning that the middleware has been bypassed?
    > 
    - 
8. Given the previous failed requests, what will most likely be the final value for the vulnerable header used to exploit the vulnerability and bypass the middleware?
    > 
    - 
9. The attacker chained the vulnerability with an SSRF attack, which allowed them to perform an internal port scan and discover an internal API. On which port is the API accessible?
    > 
    - 
10. After the port scan, the attacker starts a brute-force attack to find some vulnerable endpoints in the previously identified API. Which vulnerable endpoint was found?
    > 
    - 
11. When the vulnerable endpoint found was used maliciously for the first time?
    > 
    - 
12. What is the attack name the endpoint is vulnerable to?
    > 
    - 
13. What is the name of the file that was targeted the last time the vulnerable endpoint was exploited?
    > 
    - 
14. Finally, the attacker uses the sensitive information obtained earlier to create a special command that allows them to perform Redis injection and gain RCE on the system. What is the command string?
    > 
    - 
15. Once decoded, what is the command?
    > 
    - 