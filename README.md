# Suspected-Data-Exfiltration-Employee

# Investigation Scenario: Data Exfiltration from PIP'd Employee

## 1. Preparation 🛠️
**Goal:** Set up the hunt by defining what you're looking for.

An employee named John Doe, working in a sensitive department, recently got put on a Performance Improvement Plan (PIP). After John threw a fit, management raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (`windows-target-1`) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps.
- John is an administrator on his device and is not limited on which applications he uses.
- He may try to archive/compress sensitive information and send it to a private drive or cloud storage.

## 2. Data Collection 📊
**Goal:** Gather relevant data from logs, network traffic, and endpoints.

Consider inspecting process activity and the file system for any signs of compression or exfiltration of data.

**Activity:** Ensure data is available from all key sources for analysis.
- Ensure the relevant tables contain recent logs for your virtual machine:
  - `DeviceFileEvents`
  - `DeviceProcessEvents`
  - `DeviceNetworkEvents`

## 3. Data Analysis 🔎
**Goal:** Analyze data to test your hypothesis.

**Activity:** Look for anomalies, patterns, or indicators of compromise (IOCs).
1. **Searching for zip file creation:**
   ```kusto
   DeviceFileEvents
   | where DeviceName == "jayda-mde-0327"
   | where FileName endswith ".zip"
   | order by Timestamp desc
   ```

![image](https://github.com/user-attachments/assets/208263b8-fbf5-43ea-a4de-0fd5f14a1d60)



   - **Finding:** Regular archiving activity moving files to a `backup` folder.

1. **Correlating process events with file compression:**
   ```kusto
   let VMName = "jayda-mde-0327";
   let specificTime = datetime(2025-03-31T03:44:06.0266351Z);
   DeviceProcessEvents
   | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
   | where DeviceName == VMName
   | order by Timestamp desc
   | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
   ```

![image](https://github.com/user-attachments/assets/d49f237f-ce55-4704-a427-bb9f01221618)



   - **Finding:** PowerShell script installed 7zip and compressed employee data.

1. **Checking for exfiltration activities in network logs:**
   ```kusto
   let VMName = "jayda-mde-0327";
   let specificTime = datetime(2025-03-31T03:44:06.0266351Z);
   DeviceNetworkEvents
   | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
   | where DeviceName == VMName
   | order by Timestamp desc
   | project Timestamp, DeviceName, ActionType
   ```

![image](https://github.com/user-attachments/assets/fb2935a6-823b-4915-8875-1eb1069038a3)



   - **Finding:** Logs indicate data exfiltration via network activity.

## 4. Investigation 🕵️
**Goal:** Dig deeper into detected threats, determine their scope, and escalate if necessary.

- Logged into the suspect computer and analyzed the PowerShell script responsible for the exfiltration.


![image](https://github.com/user-attachments/assets/5ec54f11-2bc1-45b3-b06f-3fb2ba1ce1a6)


## 5. Response 🚨
**Goal:** Mitigate any confirmed threats.

- **Action Taken:** Immediately isolated the system after discovering the archiving activities.
- **Escalation:** Relayed findings to the employee’s manager, highlighting evidence of exfiltration.
- **Status:** Awaiting further instructions from management.

## 6. Documentation 📝
**Goal:** Record findings and use them to improve future hunts and defenses.

- Documented all suspicious activities, timestamps, and executed queries for reference.

## 7. Improvement 🔄
**Goal:** Improve security posture for future incidents.

- Implement **DLP (Data Loss Prevention)** policies to prevent unauthorized file transfers.
- Restrict use of PowerShell for non-admin users.
- Monitor for unexpected **file compression activities**.

---

## MITRE ATT&CK Framework - TTPs 🏴
### **Collection & Preparation for Exfiltration:**
- **T1560.001** – Archive Collected Data: **7zip used to compress employee data.**
- **T1059.001** – Command and Scripting Interpreter: **PowerShell script automating data archiving.**
- **T1036.005** – Masquerading: **Data moved to 'backup' folder to blend in.**

### **Data Exfiltration:**
- **T1048.002** – Exfiltration Over Asymmetric Encrypted Non-C2 Protocol: **Data exfiltrated over encrypted channels.**
- **T1567.002** – Exfiltration to Cloud Storage: **Possible data upload to external cloud services.**
- **T1071.001** – Application Layer Protocol: **Data transfer via HTTP/HTTPS to avoid detection.**

### **Persistence, Privilege Escalation & Evasion:**
- **T1078** – Valid Accounts: **Potential insider threat or compromised credentials.**
- **T1218.001** – Signed Binary Proxy Execution: **PowerShell execution via trusted binaries.**
- **T1070.004** – Indicator Removal: **Possible script or log deletion to cover tracks.**
