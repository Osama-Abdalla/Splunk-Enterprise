# Splunk3 BOTSv3

## Walkthrough

## 1.Investigating Amazon Web Service Cloud Events 
Scenario: Frothly's recent migration to Amazon Web Services (AWS) has introduced a new attack surface. The SOC's monitoring has detected anomalous activity within the AWS environment, suggesting a potential compromise of an Identity and Access Management (IAM) user account. The threat actor is attempting to explore, escalate privileges, and potentially exfiltrate data from S3 buckets. The goal is to use Splunk, which is ingesting AWS CloudTrail logs, to investigate this suspicious activity. You must analyze the API calls to understand the attacker's actions, identify the compromised user, and assess the impact on Frothly's cloud infrastructure.

### Key Investigation Points:
- Identify the source IP address of the suspicious activity and compare it to known corporate IP ranges to confirm external access.
- Analyze CloudTrail events for high-risk API calls, such as CreateAccessKey, CreatePolicyVersion, PutRolePolicy, or GetObject on sensitive S3 buckets.
- Determine the timeline of the attack, from initial access to attempted privilege escalation and data access.
- Map the activity to the MITRE ATT&CK Cloud Matrix, specifically techniques like:
- T1078.004 - Valid Accounts: Cloud Accounts
- T1530 - Data from Cloud Storage Object
- T1110 - Brute Force (for password guessing)
- Identify the name of any created IAM policies, access keys, or accessed S3 buckets to contain the breach.
Splunk Data Source: aws:cloudtrail

index="botsv3" sourcetype="aws:cloudtrail" IAMUser
| dedup userIdentity.userName
| table userIdentity.userName

<img width="1805" height="551" alt="image" src="https://github.com/user-attachments/assets/757cc139-1f31-4b49-8e47-0f654951df60" />
<img width="1522" height="679" alt="image" src="https://github.com/user-attachments/assets/86899403-7e45-48a0-b90e-0739e2423fd8" />

index="botsv3"  sourcetype="aws:s3:accesslogs" frothlywebcode *PUT*

<img width="1446" height="129" alt="image" src="https://github.com/user-attachments/assets/0c64f1b7-0521-4129-b7d8-6c227f9c94a9" />

index="botsv3"  sourcetype="winhostmon" source=operatingsystem
| dedup host
| table host os

<img width="1421" height="648" alt="image" src="https://github.com/user-attachments/assets/5332f29e-2cda-4be5-8e4a-43070652c8b2" />

index="botsv3"  host="BSTOLL-L" sourcetype=WinEventLog

<img width="899" height="511" alt="image" src="https://github.com/user-attachments/assets/4a429b3e-6c1c-4506-ac48-0b69f0044078" />

## 2.Crypto Miners Investigation
Scenario: Frothly's SOC has detected signs of a cryptojacking infection, with multiple servers showing abnormally high CPU usage. This suggests an attacker has compromised systems to install cryptocurrency mining software for financial gain. The investigation aims to use Splunk to find the malicious processes, determine how the infection started, and identify all affected systems.

### Key Investigation Points:
- Locate processes with names or command lines linked to cryptocurrency mining (e.g., xmr, miner, monero).
- Trace the origin of the infection by identifying parent processes and initial execution events.
- Review network connections for communication with known mining pool domains or suspicious external IPs.
- Search for dropped files, scripts, or scheduled tasks used to install or maintain the miner.
- Splunk Data Sources: Linux logs, Windows Sysmon, Stream:DNS, Stream:HTTP

index="botsv3" sourcetype="PerfmonMk:Process" process_cpu_used_percent=100
<img width="800" height="434" alt="image" src="https://github.com/user-attachments/assets/2766cd99-0c83-4653-b370-b17b52029042" />
<img width="1782" height="471" alt="image" src="https://github.com/user-attachments/assets/e7a444d5-f2db-46a3-ac5c-af8057822804" />

## 3.Investigating Authentication Events in Amazon Web Service
Scenario: Frothly's security team has observed a series of suspicious sign-in attempts within their Amazon Web Services (AWS) environment. There are concerns that an attacker may be attempting to gain unauthorized access to cloud resources using stolen or brute-forced credentials. This investigation uses Splunk, ingesting AWS CloudTrail logs, to analyze authentication events, identify malicious login behavior, and determine if any accounts have been compromised.

### Key Investigation Points:
- Identify failed login attempts and repeated authentication failures from unusual IP addresses or locations.
- Analyze successful logins to detect access from unexpected geographic regions or at anomalous times.
- Investigate API calls following successful logins for unusual or high-risk actions.
- Determine if multi-factor authentication (MFA) was used during sign-in events.
Splunk Data Source: aws:cloudtrail

Splunk Data Sources: Windows Sysmon, Windows Event Logs
index="botsv3" sourcetype="aws:cloudtrail" "userIdentity.type"=IAMUser eventSource="iam.amazonaws.com" errorCode!=success
|stats dc(errorMessage) by userIdentity.accessKeyId

<img width="1788" height="462" alt="image" src="https://github.com/user-attachments/assets/7f3d2576-524e-4e8d-8a5a-3988d8b3c471" />

index="botsv3" sourcetype="stream:smtp" *case*

<img width="949" height="570" alt="image" src="https://github.com/user-attachments/assets/5a6a5d45-1774-4e89-8b68-64937f9773b6" />
<img width="1280" height="462" alt="image" src="https://github.com/user-attachments/assets/d2b94c6f-a309-48bc-aed3-1c43b8e8e2b0" />

<img width="899" height="417" alt="image" src="https://github.com/user-attachments/assets/272022ad-9c50-4d5d-b469-fcc63494bd9c" />

index="botsv3"  sourcetype="aws:cloudtrail" userIdentity.accessKeyId="AKIAJOGCDXJ5NW5PXUPA" eventName=CreateAccessKey

<img width="800" height="187" alt="image" src="https://github.com/user-attachments/assets/3ee59ff0-10ba-4fb1-b0db-db24537f592c" />

index="botsv3"  sourcetype="aws:cloudtrail" userIdentity.accessKeyId="AKIAJOGCDXJ5NW5PXUPA" eventName=DescribeAccountAttributes

<img width="1115" height="299" alt="image" src="https://github.com/user-attachments/assets/e862d5a8-000f-45ae-b5af-37b9e91c350b" />

## 4.Investigating Microsoft Office Macro Malware Events with Splunk
Scenario: Frothly's SOC has been alerted to a potential malware infection originating from a malicious Microsoft Office document. The attack appears to involve a macro-enabled file that, when opened, executed a malicious payload. This is a common technique for initial network access. The goal of this investigation is to use Splunk to analyze endpoint and process execution logs to find the malicious document, trace the execution chain of the macro, and identify any payloads delivered to the system.

### Key Investigation Points:
- Identify Microsoft Office processes (e.g., winword.exe, excel.exe) with suspicious child processes.
- Analyze command-line arguments for evidence of macro execution or script-based payloads.
- Locate the malicious document and examine its origin (e.g., email attachment, web download).
- Trace any network connections or file modifications following the macro execution.

index="botsv3"  sourcetype="ms:o365:management" Workload=OneDrive Operation=FileUploaded
| table _time ClientIP ObjectId UserId UserAgent

<img width="1779" height="663" alt="image" src="https://github.com/user-attachments/assets/ebab8b3c-80a2-4057-b5e1-cfd439aaf05e" />

index="botsv3"  sourcetype="stream:smtp" *alert* "attach_filename{}"="Malware Alert Text.txt"

<img width="1363" height="454" alt="image" src="https://github.com/user-attachments/assets/0028efed-4ab0-4001-84f4-0b0c722cfed3" />
<img width="1090" height="746" alt="image" src="https://github.com/user-attachments/assets/8b241e6a-f394-4850-9646-d5e3c0677c58" />

index="botsv3"  sourcetype="xmlwineventlog"  *xlsm*

<img width="1280" height="244" alt="image" src="https://github.com/user-attachments/assets/a915e7f7-eb42-4078-a4b4-2df47eb07be8" />

index="botsv3"  (useradd OR adduser) source="/var/log/auth.log"

<img width="1277" height="382" alt="image" src="https://github.com/user-attachments/assets/33b5fe17-3048-423a-b535-9e0e5533ace0" />

index="botsv3"  tomcat7 sourcetype="osquery:results"

<img width="1386" height="245" alt="image" src="https://github.com/user-attachments/assets/fa3cc444-cddc-4193-9263-eb4567c7bcbc" />

index="botsv3"  sourcetype="wineventlog" EventCode="4720"

<img width="785" height="301" alt="image" src="https://github.com/user-attachments/assets/8dddffe8-6c64-4ced-b7f2-fe27b5f2a0fd" />

index="botsv3"  sourcetype="wineventlog" svcvnc EventCode=4732

<img width="754" height="331" alt="image" src="https://github.com/user-attachments/assets/cde385ca-bf2a-49b0-9aab-1f94d15fd193" />

<img width="885" height="429" alt="image" src="https://github.com/user-attachments/assets/e3900cee-0dab-46cc-bc0d-90bac8c452b7" />

index="botsv3"  1337  sourcetype="osquery:results" "columns.port"=1337

<img width="1404" height="238" alt="image" src="https://github.com/user-attachments/assets/c9e7401b-e198-46cd-a560-015d04609559" />

<img width="1737" height="858" alt="image" src="https://github.com/user-attachments/assets/c9a06c60-4564-4ca7-ba19-9ae18c71c2d2" />

## 5.Investigating Compromised Machines
Scenario: Frothly's SOC has identified indicators that one or more endpoints within the network have been compromised. The attacker's activities range from unauthorized data access to potential lateral movement. This investigation aims to use Splunk to examine endpoint logs, detect malicious processes, investigate network connections, and uncover persistence mechanisms to fully understand the scope of the breach.

### Key Investigation Points:
- Identify unusual processes, especially those with suspicious parent-child relationships or command-line arguments.
- Analyze network connections for communication with known malicious domains or unexpected external IP addresses.
- Investigate file system and registry modifications for evidence of persistence, such as malicious scheduled tasks or service installations.
- Correlate events across multiple data sources to build a timeline of attacker activity on the host.
- Splunk Data Sources: Windows Sysmon, Windows Security Events, Stream:HTTP, Stream:DNS

index="botsv3"  sourcetype="stream:http" dest_port=3333

<img width="1404" height="267" alt="image" src="https://github.com/user-attachments/assets/12d0551f-e249-4951-b036-3c651dd9b2ba" />

index="botsv3"  sourcetype="stream:smtp" "receiver_email{}"="ghoppy@froth.ly"

<img width="1081" height="618" alt="image" src="https://github.com/user-attachments/assets/2ecc0255-e801-47fb-aee0-c585e1025817" />

index="botsv3" source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message="*/x"
| rex field=Message "\$t\=\'\'"
| table url

<img width="371" height="382" alt="image" src="https://github.com/user-attachments/assets/dbd9bca7-c1a5-4208-aff1-b8cfefced131" />

index="botsv3" "/news.php" OR "/admin/get.php" OR "/login/process.php"

<img width="800" height="324" alt="image" src="https://github.com/user-attachments/assets/4556efab-8d35-4a01-9ffc-856b9f64929a" />












