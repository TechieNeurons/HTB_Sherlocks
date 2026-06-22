Task 1 - What is the MD5 hash of the malware?
> 6bba36e9f169c54e7e353163308a0abc

Task 2 - The malware creates a lock on a file to ensure that only one instance of it is running. What is the full path of that file?
> strings antarctica | grep tmp --> /tmp/file.lock

Task 3 - The malware checks if a specific module is loaded as part of its anti-VM checks. What is the name of that module?
> vboxguest

Task 4 - The malware reads the content of files within a specific directory, searching for certain strings as part of its anti-VM checks. What is the full path of this directory?
> /sys/class/dmi/id/

Task 5 - What is the SSH key that the malware added?
> ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCfCBTevpqxa0M8DzpdWfpTxEhbSf2/HjbYoIPlqGI4uNa23JpydpQFIlLRQh7Y+1dX2jmrZojE+uM6nQb+lkTR7fadCmKTOZZBAaQY2ld6OfSXfaxbfl2JXWGKtUf/Q+uLMazNhWR+4xXmJfeFkRMq/LZVTShB5NOZPHrEAK57QiQpD1Y+efK99z8gspMPk+YUEYYJQZBLXzm83nbOZVzNs7vIYAi03stTNA/tCyEkX7+854GI5LWLseoJWT/hSX7dzdIhED1pzleNho/zPA5E1X+encRGz/ln/HhYygaxAS+K3/j5A2a/Idiy9ZEdf/C6zVW+Qh8sMg54kniggRF4jozfL9CGdAMwBHH03+ivxn3EdMf1fQ2oEkEVdqIZxqcVGR7BG35B+WOQAyJIm2vJqK5OS1KoD70cf3EnnRhnnq66r9VUABswruPes48YRDHZOeNOKW+6e+/JxEcg5TPR2iQSYLirBpmbkBwa+0c6WNxRjAslbAOOP5rbQlv+BYs= null@debian

*First done, in the strings, big base64 when decoded we get that*

Task 6 - What component of Linux does the malware use to watch for file changes?
> inotify

Task 7 - What file does the malware track for changes?
> .bash_history

Task 8 - What protocol does the malware use to exfiltrate data to its server?
> dns

Task 9 - What is the FQDN the malware tries to connect to?
> myserver.invalid.com