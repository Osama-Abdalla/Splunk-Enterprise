# Splunk BOTSv2

## Walkthrough
## 1.Web Investigation
Scenario: This investigation focuses on Amber Turing, an employee at the fictional company Frothly. After a failed acquisition attempt by a potential competitor, Amber used her work computer to visit the competitor's website, find executive contact information, and send emails. The goal is to use Splunk to trace her web and email activity.

### Key Skills Demonstrated:
- Analyzing proxy and web logs in Splunk.
- Investigating email events (SMTP).
- Correlating events to build a timeline of user activity.
- Using advanced SPL to extract specific data points.

<img width="1792" height="922" alt="image" src="https://github.com/user-attachments/assets/afb074a5-028d-48c0-abd0-c2e3b7e3f362" />
<img width="1782" height="833" alt="image" src="https://github.com/user-attachments/assets/9d633693-8338-41d4-a09c-91573d1afaf3" />
<img width="760" height="608" alt="image" src="https://github.com/user-attachments/assets/cfa4a439-3b31-4566-9a82-742b41948119" />
<img width="800" height="339" alt="image" src="https://github.com/user-attachments/assets/3ddaee1e-ef7b-4be8-9e41-b23cdd9dbb6b" />
<img width="1783" height="815" alt="image" src="https://github.com/user-attachments/assets/702976e1-b00c-4901-b608-0d19a965d59c" />
<img width="1529" height="855" alt="image" src="https://github.com/user-attachments/assets/8f5de99c-a119-4bab-b7ff-59612cece57f" />


## 2.Web Application Attacks
Scenario: The Frothly web application infrastructure is under active attack. An external threat actor is attempting to identify and exploit vulnerabilities in the company's public-facing websites. This includes attempts at SQL injection, cross-site scripting (XSS), and path traversal. The Security Operations Center (SOC) has received alerts regarding anomalous HTTP traffic. The goal is to use Splunk to analyze web server logs (stream:http), identify the attack techniques, determine if they were successful, and attribute the activity to a source IP address.

### Key Investigation Points:
- Identify malicious HTTP requests containing common attack patterns and payloads.
- Determine the source IP address of the attacker.
- Analyze the success or failure of the attack attempts based on server response codes.
- Categorize the attacks using the MITRE ATT&CK framework (e.g., Technique T1190: Exploit Public-Facing Application).

<img width="1782" height="883" alt="image" src="https://github.com/user-attachments/assets/a7e40f86-90ff-4a4c-bf95-9ded21e4102c" />
<img width="1224" height="683" alt="image" src="https://github.com/user-attachments/assets/c255e709-5377-447e-85b4-539d2833c560" />

index="botsv2" site="www.brewertalk.com"

<img width="837" height="610" alt="image" src="https://github.com/user-attachments/assets/f4880f77-2770-43b0-a92e-4b781602cbb5" />

index="botsv2" site="www.brewertalk.com" src_ip="45.77.65.211"

<img width="800" height="673" alt="image" src="https://github.com/user-attachments/assets/6f8016ee-dbb8-4248-9da9-415b7fbf2b47" />
<img width="1785" height="818" alt="image" src="https://github.com/user-attachments/assets/fbe11965-219e-45eb-861d-652954f86499" />
<img width="1186" height="503" alt="image" src="https://github.com/user-attachments/assets/e5332bdd-5081-4dec-ba81-8df25139e196" />

## 3.USB Attacks
Scenario: Frothly's endpoint detection system has flagged potential policy violations involving removable media. Specifically, the SOC needs to investigate if any employees have connected unauthorized USB devices to their corporate workstations. The insertion of such devices can be a precursor to data exfiltration or malware installation. The goal is to use Splunk to analyze Windows Event Logs (e.g., EventCode 6416 for Windows 10) to detect USB mass storage device activity, identify the user and host involved, and determine the vendor of the USB device.

### Key Investigation Points:
- Identify event logs corresponding to the installation of a USB mass storage device.
- Correlate the event timestamps with user logon data to identify the responsible employee.
- Extract the device vendor ID, product ID, and serial number from the logs for further analysis.
- Investigate subsequent network or file activity for signs of data exfiltration.

index="botsv2"  host="MACLORY-AIR13" (*.ppt OR *.pptx)

<img width="1787" height="762" alt="image" src="https://github.com/user-attachments/assets/2a20dc77-2ace-440c-aad5-8d7b2cd40fab" />

index="botsv2"  host="MACLORY-AIR13"  sourcetype=ps *.crypt NOT *.pdf

<img width="1824" height="766" alt="image" src="https://github.com/user-attachments/assets/5aa9ac4b-8aa0-4845-b8ad-0f9f6a5b8e6a" />

index="botsv2" host="kutekitten" sourcetype=osquery_results "\\/Users\\/mkraeusen" "columns.target_path"="/Users/mkraeusen/Downloads/Important_HR_INFO_for_mkraeusen"

<img width="1473" height="254" alt="image" src="https://github.com/user-attachments/assets/001aa034-ca43-4d69-beaf-76ed4021c873" />
<img width="1544" height="765" alt="image" src="https://github.com/user-attachments/assets/36882d26-8851-4daa-949a-4efa17433de9" />

## 4.Investigating FTP
Scenario: As part of the ongoing investigation into Amber Turing, the SOC has expanded its scope to include all file transfer protocol (FTP) activity. FTP is often used for the unauthorized transfer of large files due to its simplicity. The goal is to use Splunk to analyze FTP command logs (stream:ftp) to discover if any sensitive company documents, such as the "Frothly_Acquisition_Plans.pdf" file, were transferred to an external server. This involves identifying FTP sessions, successful login attempts, file uploads/downloads, and correlating this activity with specific users.

Key Investigation Points:
- Identify all FTP sessions initiated from within the Frothly network.
- Determine if Amber Turing or other users successfully logged into an external FTP server.
- Find evidence of file uploads (e.g., PUT command) to a remote server, specifically the acquisition plans document.
- Identify the external IP address of the FTP server used for the transfer.

<img width="1280" height="754" alt="image" src="https://github.com/user-attachments/assets/ca308f37-b387-4900-98a7-c04715fba8da" />

index="botsv2" sourcetype="stream:tcp" 45.77.65.211

<img width="771" height="341" alt="image" src="https://github.com/user-attachments/assets/65f70ed3-c9a6-4d0f-9b7c-f7a230535afe" />
<img width="1673" height="754" alt="image" src="https://github.com/user-attachments/assets/0011a2aa-945d-4b3d-9549-cd2c5a1c201e" />
<img width="1439" height="731" alt="image" src="https://github.com/user-attachments/assets/64664046-b4c8-49e8-a747-e21276b2ea83" />
<img width="1098" height="866" alt="image" src="https://github.com/user-attachments/assets/db4a8b1f-e9a6-438f-a559-15602cade09d" />








