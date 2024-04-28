# OpTinselTrace 2

## Speech
```
It seems our precious technology has been leaked to the threat actor. Our head Elf, PixelPepermint, seems to think that there were some hard-coded sensitive URLs within the technology sent. Please audit our Sparky Cloud logs and confirm if anything was stolen! PS - Santa likes his answers in UTC...
```

## Analysis


## Questions
1. What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?
    - 62d5c1f1f9020c98f97d8085b9456b05
2. What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?
    - 2023-11-29 08:24:07
3. What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?
    - 2023-11-29 08:24:16
4. Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?
    - python
5. Which file did the Threat Actor locate some hard coded credentials within?
    - claus.py
6. Please detail all confirmed malicious IP addresses. (Ascending Order)
    - 45.133.193.41, 191.101.31.57
7. We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.
    - bytesparkle.ovpn, 2023-11-29 10:16:53
8. Please confirm the username of the compromised AWS account?
    - elfadmin
9. Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?
    - arn:aws:s3:::papa-noel