# Nubilum 2

## Speech
```
Leading telecoms provider Forela uses AWS S3 as an essential part of their infrastructure. They can deploy applications quickly and do effective analytics on their sizable dataset thanks to it acting as both an application storage and a data lake storage. Recently, a user reported an urgent issue to the helpdesk: an inability to access files within a designated S3 directory. This disruption has not only impeded critical operations but has also raised immediate security concerns. The urgency of this situation demands a security-focused approach. Reports of a misconfigured S3 Bucket policy for the forela-fileshare bucket, resulting in unintended public access, highlight a potential security vulnerability that calls for immediate corrective measures. Consequently, a thorough investigation is paramount.
```

## Analysis
Using SOF-ELK

1. Install the VM sof-elk, connect via ssh as elk_user (password = forensics)
2. After extracting the nubilum_2.zip, scp the file to the sof-elk : `scp -r nubilum_2/949622803460/CloudTrail elk_user@192.168.112.175:/home/elk_user/tmp/`
3. In sof-elk ingest every json with the ingestion script : `find /home/elk_user/tmp/ -name '*.json' -execdir /usr/local/sof-elk/supporting-scripts/aws-cloudtrail2sof-elk.py -r {} -w /logstash/aws/{} \;`
4. After few minutes, I have 27,104 records in the `aws-*` index, 244 are from the sof-elk install and date from the install, the others are the one of the challenge and date from *2023-10-20* to *2023-11-03*
5. The speech gave us some insight, we are looking for unauthorized access to s3 bucket, let's begin by looking at the IP :
     - Write ip in the *search field* bar
     - We have three IP : 52.77.60.127, 54.242.59.197, 35.153.199.23
     - The first one is used in 99% of the logs, so it's probably a legitimate one, because we can suppose the attacker didn't made 99% of the request done to the s3, don't forget the s3 is in production so used by legitimate user
6. Let's filter on the second IP address (by clicking and the little + at the right of : 54.242.59.197)
     - We have 223 hits, starting at **2023-11-02 14:43:01** and finishing at **2023-11-02 15:29:29**
7. Now I'll open the first hit and take note of every field that could be interesting :
     - bucket_name : "forela-fileshare"
     - useragent : python-requests/2.31.0
     - @timestamp
     - event_name : "ListObjects"
8. After I go to the search bar for fields and filter the fields I find previously to see what value they can have, to have an idea of what he did, the most interesting one is event_name where we can see one event_name is "GetObject" (dl file), I think we can get the name of the object downloaded, let's find the field for the object downloaded
     - filter on GetObject and look at the json
     - aws_resource_name is interesting
9. Now I'll remove the filter on GetObject and create a table with all the fields I previously mentionnend to get an overview of all the actions done by the Attacker
     - to add a column I search for the field and click on the + button "add column"
     ![Overview attacker](../../img/nubilum_2/00_overview_attacker.png)
10. The attacker begin with listing all files
     - Then he download multiple files
     - He took informations about the environnements via API calls like **GetCallerIdentity**, **ListAccountAliases**, **DescribeAddresses**, **DescribeSecurityGroups**, **DescribeHosts**, etc.
     - He escalate his privileges, we can see that by looking at the access_key_id changing
     - He add a policy via **PutUserPolicy** eventName to gain full privileges
     - He download more files with `GetObject` (with some `ListObjects`)
     - Then He made copy, we can take a look at this log :
     ```
     "raw_request_parameters": "{\"x-amz-copy-source\":\"forela-fileshare/customer_data/customer-data4.csv\",\"x-amz-server-side-encryption\":\"aws:kms\",\"x-amz-server-side-encryption-aws-kms-key-id\":\"arn:aws:kms:us-east-1:263954014653:key/mrk-85e24f85d964469cba9e4589335dd0f4\",\"key\":\"customer_data/customer-data4.csv\"}"
     ```
     - With this log we see the file is copied and encrypted
     - Then he upload the file README2DECRYPT.txt to the aws
     - He install a persistance via **CreateAccessKey** (a new access key)
11. by taking a look at the **CreateAccessKey** log we see :
     - A key for the user **forela-admin**
     ```
     "eventTime": "2023-11-02T15:26:53Z",
     "eventSource": "iam.amazonaws.com",
     "eventName": "CreateAccessKey",
     "awsRegion": "us-east-1",
     "sourceIPAddress": "54.242.59.197",
     "userAgent": "aws-cli/2.12.0 Python/3.11.4 Linux/6.3.0-kali1-cloud-amd64 source/x86_64.kali.2023 prompt/off command/iam.create-access-key",
     "requestParameters": {
     "userName": "forela-admin"
     },
     "responseElements": {
     "accessKey": {
          "accessKeyId": "AKIA52GPOBQCAB3EEAXZ",
          "status": "Active",
          "userName": "forela-admin",
          "createDate": "Nov 2, 2023 3:26:53 PM"
     }
     },
     ```

### Some jq
1. Access Key Id :
     - `find . -type f -name '*.json' -exec jq '.Records[] | select(.sourceIPAddress == "54.242.59.197") | .userIdentity.userName' {} + | sort | uniq -c | sort`
     ```
     128 "dev-policy-specialist"
     15 null
     15 "prod-VPC-readonly"
     18 "prod-S3-readonly"
     32 "prod-EC2-readonly"
      6 "dev-access-auditor"
      9 "prod-IAM-readonly"
     ```
     - `find . -type f -name '*.json' -exec jq '.Records[] | select(.sourceIPAddress == "54.242.59.197") | .userIdentity.acessKeyId' {} + | sort | uniq -c | sort`
     ```
     128 "AKIA52GPOBQCMBGZADBX"
     15 "AKIA52GPOBQCAVX7ZPB5"
     15 null
     18 "AKIA52GPOBQCFWV5UO5O"
     32 "AKIA52GPOBQCLJPSAI53"
      6 "AKIA52GPOBQCGVDLFLNB"
      9 "AKIA52GPOBQCIAO45DBK"
     ```

## Questions
1. What was the originating IP address the Threat Actor (TA) used to infiltrate the Forela’s AWS account?
     > 54.242.59.197
     - cf. Analysis > 5
2. What was the time, filename, and Account ID of the first recorded s3 object accessed by the TA?
     > 2023-11-02T14:52:03Z,prod-EC2-readonly_accessKeys.csv,anonymous
     - I begin by taking a look at sof-elk and noticed that the json parsed by sof-elk doesn't contain the Account ID (nowhere)
     - So I used jq, and used this command : `find . -type f -name '*.json' -exec jq '.Records[] | select(.eventName == "GetObject") | {eventName, eventTime, accountId: .userIdentity.accountId, requestParameters}' {} + | jq -s 'sort_by(.eventTime)'`
3. How many Access Keys were compromised, at a minimum?
     > 7
     - Not sure If I understand correctly... I did that : `find . -type f -name '*.json' -exec jq '.Records[] | select(.sourceIPAddress == "54.242.59.197") | .userIdentity.userName' {} + | sort | uniq -c | sort`
     - With this command we have all the users used by the attacker we can replace `userIdentity.userName` by `userIdentity.accessKeyId` in order to get the access key of each user
     - I see 6 access key id and one **null** but the answer is 7... The null count ?
4. The TA executed a command to filter EC2 instances. What were the name and value used for filtering?
     > instance-state-name:running
     - `find . -type f -name '*.json' -exec jq '.Records[] | select(.sourceIPAddress == "54.242.59.197" and .eventName == "DescribeInstances")' {} +`
     - The attacker looked for running instances of EC2
5. Can you provide the count of unsuccessful discovery and privilege escalation attempts made by the TA before gaining elevated access with the compromised keys?
     > 42
     - `find . -type f -name '*.json' -exec jq '.Records[] | select(.sourceIPAddress == "54.242.59.197" and .errorMessage)' {} + | grep errorMessage | wc -l`
     - We count the number of errorMessage
6. Which IAM user successfully gained elevated privileges in this incident?
     > dev-policy-specialist
     - By lookking at the logs in elk we see the acessKeyId changing from one to another, he switch from one user to the next one until he get this one
7. Which event name permitted the threat actor to generate an admin-level policy?
     > PutUserPolicy
     - After he gain access as **dev-policy-specialist** we see multiple EventName linked with policier and then we see this one PutUserPolicy, the attacker add a policy
     - A policy to get more right (admin)
8. What is the name and statement of the policy that was created that gave a standard user account elevated privileges?
     > sbhyy79zky,[{"Effect": "Allow","Action": "*","Resource": "*"}]
     - By looking at the log adding the policy we find the name of the policy and the statement, we can find easily with : `find . -type f -name '*.json' -exec jq '.Records[] | select(.sourceIPAddress == "54.242.59.197" and .eventName == "PutUserPolicy")' {} +`
     - The attacker allow erverything (any actions) on everything with this statement
9. What was the ARN (Amazon Resource Name) used to encrypt the files?
     > arn:aws:kms:us-east-1:263954014653:key/mrk-85e24f85d964469cba9e4589335dd0f4
     - cf. Analysis > 10
10. What was the name of the file that the TA uploaded to the S3 bucket?
     > README2DECRYPT.txt
     - cf. Analysis > 10
11. Which IAM user account did the TA modify in order to gain additional persistent access?
     > forela-admin
     - cf. Analysis > 11
12. What action was the user not authorized to perform to view or download the file in the S3 bucket?
     > kms:Decrypt
     - I think it's link with the action a legitimate user try to do after the attacker encrypt the files
     - Need to look at errorMessage (not just the one from the attacker)