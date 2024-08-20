# Tracer

## Speech
```
A junior SOC analyst on duty has reported multiple alerts indicating the presence of PsExec on a workstation. They verified the alerts and escalated the alerts to tier II. As an Incident responder you triaged the endpoint for artefacts of interest. Now please answer the questions regarding this security event so you can report it to your incident manager.
```

## Analysis

## Questions
1. The SOC Team suspects that an adversary is lurking in their environment and are using PsExec to move laterally. A junior SOC Analyst specifically reported the usage of PsExec on a WorkStation. How many times was PsExec executed by the attacker on the system?
    > 9
2. What is the name of the service binary dropped by PsExec tool allowing attacker to execute remote commands?
    > psexesvc.exe
3. Now we have confirmed that PsExec ran multiple times, we are particularly interested in the 5th Last instance of the PsExec. What is the timestamp when the PsExec Service binary ran?
    > 07/09/2023 12:06:54
4. Can you confirm the hostname of the workstation from which attacker moved laterally?
    > Forela-Wkstn001
5. What is full name of the Key File dropped by 5th last instance of the Psexec?
    > PSEXEC-FORELA-WKSTN001-95F03CFE.key
6. Can you confirm the timestamp when this key file was created on disk?
    > 07/09/2023 12:06:55
7. What is the full name of the Named Pipe ending with the "stderr" keyword for the 5th last instance of the PsExec?
    > \PSEXESVC-FORELA-WKSTN001-3056-stderr