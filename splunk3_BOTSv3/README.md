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

