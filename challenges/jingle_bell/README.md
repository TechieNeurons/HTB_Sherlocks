# Jingle Bell

## Speech
```
Torrin is suspected to be an insider threat in Forela. He is believed to have leaked some data and removed certain applications from their workstation. They managed to bypass some controls and installed unauthorised software. Despite the forensic team's efforts, no evidence of data leakage was found. As a senior incident responder, you have been tasked with investigating the incident to determine the conversation between the two parties involved.
```

## Analysis
```
$ tree
.
└── C
    └── Users
        └── Appdata
            └── Local
                └── Microsoft
                    └── Windows
                        └── Notifications
                            ├── wpndatabase.db
                            ├── wpndatabase.db-shm
                            ├── wpndatabase.db-wal
                            └── wpnidm

9 directories, 3 files
```
1. only one file `wpndatabase.db` which is a sqlite db, seems to be the windows notifications (the one appearing in the bottom right)
2. Open with `sqlitebrowser`
3. I think only one table interesting, the `Notification`
4. By looking at the `payload` column we have some interesting information
5. After looking at all the payload I can say that :
    - the one beginning with `<title>` are from xboxlive or other ininteresting things of microsoft
    - The xml one are dumb too, no point, link to onedrive or onenote, we don't care
6. The messages interesting are the one beginning by `<toast` because they are from **slack**, the first one is from the slackbot and don't tell anything....
![toast](./img/00_toast.png)
7. The inside is some HTML, here is the first one :
```HTML
<toast activationType="protocol" launch="slack://channel?id=D0544UUC4UB&amp;message=1681985806.920359&amp;team=T054518ADUJ&amp;origin=notification"><header id="T054518ADUJ" title="PrimeTech Innovations" activationType="protocol" arguments="slack://channel?team=T054518ADUJ"></header><visual><binding template="ToastGeneric"><text hint-wrap="false" hint-maxLines="1">New message from cyberjunkie</text><text hint-maxLines="10" hint-style="bodySubtle" hint-wrap="true">Cyberjunkie-PrimeTechDev accepted your invitation to join Slack — take a second to say hello.</text><image placement="appLogoOverride" hint-crop="circle" src="C:/Users/CYBERJ~1/AppData/Local/Temp/Notification Cache/35f6a85490effd9267c1e097b456bc77.png"/></binding></visual><audio silent="true"/></toast>
```
And after a little bit of beautify stuff :
```HTML
<toast activationType="protocol" launch="slack://channel?id=D0544UUC4UB&amp;message=1681985806.920359&amp;team=T054518ADUJ&amp;origin=notification">
  <header id="T054518ADUJ" title="PrimeTech Innovations" activationType="protocol" arguments="slack://channel?team=T054518ADUJ"></header>
  <visual>
    <binding template="ToastGeneric">
      <text hint-wrap="false" hint-maxLines="1">New message from cyberjunkie</text>
      <text hint-maxLines="10" hint-style="bodySubtle" hint-wrap="true">Cyberjunkie-PrimeTechDev accepted your invitation to join Slack — take a second to say hello.</text>
      <image placement="appLogoOverride" hint-crop="circle" src="C:/Users/CYBERJ~1/AppData/Local/Temp/Notification Cache/35f6a85490effd9267c1e097b456bc77.png" />
    </binding>
  </visual>
  <audio silent="true" />
</toast>
```
Two interesting things, this line : `<text hint-wrap="false" hint-maxLines="1">New message from cyberjunkie</text>` which is the "object" of the notification and : `<text hint-maxLines="10" hint-style="bodySubtle" hint-wrap="true">Cyberjunkie-PrimeTechDev accepted your invitation to join Slack — take a second to say hello.</text>` which is the text of the application
8. let's get all the text of every message :
```
New message from cyberjunkie
Cyberjunkie-PrimeTechDev accepted your invitation to join Slack — take a second to say hello.
      
New message in #forela-secrets-leak
Cyberjunkie-PrimeTechDev: Hello torrin, did you managed to find the files related to the the Forela Oil extraction plan in Angola?

New message in #forela-secrets-leak
Cyberjunkie-PrimeTechDev: Just to confirm as we dont want forela's IT team to get suspicious Password for the archive server is :"Tobdaf8Qip$re@1"
    
New message in #forela-secrets-leak
Cyberjunkie-PrimeTechDev: Confirmation that password is "Tobdaf8Qip$re@1"

New message in #forela-secrets-leak
Cyberjunkie-PrimeTechDev: Okay so i am sending you a google drive link where you can upload all other information you gathered so far.

New message in #forela-secrets-leak
Cyberjunkie-PrimeTechDev: https://drive.google.com/drive/folders/1vW97VBmxDZUIEuEUG64g5DLZvFP-Pdll?usp=sharing , remember to upload the documents and pdfs too

New message in #forela-secrets-leak
Cyberjunkie-PrimeTechDev: Bank Account Number: 03135905179789 Sent 10,000 £ to the above account as promised, cheers
```
I think we can answer everything with that... I think we can't get more...

## Questions
1. Which software/application did Torrin use to leak Forela's secrets?
    - Slack
    - cf. analysis > 6
2. What's the name of the rival company to which Torrin leaked the data?
    - PrimeTech Innovations
    - Nee to look at the first toast, the one before the toast we see on the screenshot
3. What is the username of the person from the competitor organization whom Torrin shared information with?
    - Cyberjunkie-PrimeTechDev
    - cf. analysis > 8
4. What's the channel name in which they conversed with each other?
    - forela-secrets-leak
    - cf. analysis > 8
5. What was the password for the archive server?
    - Tobdaf8Qip$re@1
    - cf. analysis > 8
6. What was the URL provided to Torrin to upload stolen data to?
    - https://drive.google.com/drive/folders/1vW97VBmxDZUIEuEUG64g5DLZvFP-Pdll?usp=sharing
    - cf. analysis > 8
7. When was the above link shared with Torrin?
    - 2023-04-20 10:34:49
    - Look at the toast with the drive link, we have timestamp in the messages, for this one the timestamp is : `1681986889.660179`, we get it in the first tag : `<toast activationType="protocol" launch="slack://channel?id=C05451QSQM8&amp;message=1681986889.660179&amp;team=T054518ADUJ&amp;origin=notification">`, when we convert ([here](https://www.epochconverter.com/) for example) we get the good timestamp
8. For how much money did Torrin leak Forela's secrets?
    - £10000
    - cf. analysis > 8