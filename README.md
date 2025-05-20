# Threat Hunt Report: Suspicious Creation of Hidden Folder and File
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-unauthorized-use-of-built-in-remote-assistance-tools/blob/main/threat-hunting-scenario-unauthorized-use-of-built-in-remote-assistance-tools-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Windows built-in tools: msra.exe, cmd.exe, explorer.exe

##  Scenario

Security monitoring detected suspicious use of Microsoft Remote Assistance (msra.exe), a built-in Windows tool that allows a user to offer remote help to another system. The threat actor launched msra.exe with the /offerra flag via command-line to initiate unauthorized remote assistance sessions to multiple devices.

To maintain operational security and evade detection, the attacker documented their targets and session details in a file named remote-control-notes.txt saved to the desktop, and then deleted the file shortly afterward to remove evidence of the operation.

The hunt aims to identify unauthorized use of msra.exe and track file artifacts that may have briefly existed as operational notes.

### High-Level TOR-Related IoC Discovery Plan

- **Check DeviceProcessEvents** for executions of msra.exe initiated by explorer.exe, which may signal manual, user-initiated activity via the Run window or Start Menu.
- **Check DeviceProcessEvents** for any execution of msra.exe, particularly where the ProcessCommandLine includes the /offerra flag, indicating an unsolicited Remote Assistance session attempt.
- **Check DeviceFileEvents** for creation of a file named remote-control-notes.txt on the desktop, which may have been used by the attacker to track or log remote assistance sessions.

---

## Steps Taken

### 1. Detected Execution of msra.exe from GUI (explorer.exe)

To identify potential manual launches of the Microsoft Remote Assistance tool, I queried the DeviceProcessEvents table for instances where msra.exe was executed with explorer.exe as the initiating process. This typically suggests the tool was launched through the graphical user interface, such as the Start Menu or the Run dialog (Win + R → msra.exe). On 2025-05-20T00:13:43.0482142Z, the user "huy" on the device "huy" manually launched msra.exe via explorer.exe, indicating the Remote Assistance tool was opened through the graphical interface.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where FileName == "msra.exe"
| where InitiatingProcessFileName == "explorer.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

<img width="851" alt="Screenshot 2025-05-19 at 8 49 27 PM" src="https://github.com/user-attachments/assets/9cef0d73-a313-4d4e-9ebc-4ce42b03cfa6" />

---

### 2. Identified Suspicious Use of msra.exe with /offerra Flag

I investigated command-line executions of msra.exe with the /offerra switch, which is used to initiate unsolicited Remote Assistance sessions to other systems. On May 19, 2025, between 8:15:19 PM and 8:16:25 PM UTC, the user "huy" on the device "huy" executed four Remote Assistance commands targeting different hosts:

msra.exe /offerra PC1234 at 2025-05-20T00:15:19.0569006Z

msra.exe /offerra John-PC at 2025-05-20T00:15:51.8459403Z

msra.exe /offerra WIN-TEST01 at 2025-05-20T00:16:08.1419023Z

msra.exe /offerra Desktop-Dev01 at 2025-05-20T00:16:25.563026Z

These repeated attempts to initiate unsolicited Remote Assistance sessions to various internal systems strongly suggest suspicious lateral movement activity. The fact that all commands were executed from the same user account and endpoint further supports the likelihood of unauthorized access attempts.

**Query used to locate event:**
```kql
DeviceProcessEvents
| where FileName == "msra.exe"
| where ProcessCommandLine contains "/offerra"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

<img width="885" alt="Screenshot 2025-05-19 at 9 02 59 PM" src="https://github.com/user-attachments/assets/7c9685bf-e0d4-4b4c-8edd-361fe54a89d7" />

---

## Chronological Event Timeline 

### 1. Hidden folder named secret_stuff was created and set to hidden attribute by user huy.

- **Timestamp:** 2025-05-19T21:20:08.0000000Z
- **Event:** The folder C:\Users\huy\Documents\secret_stuff was hidden using the Windows attrib +h command.
- **Action:** The folder was intentionally concealed from casual view to evade detection.
- **Command:** attrib.exe +h C:\Users\huy\Documents\secret_stuff

### 2. A PowerShell script named runme.ps1 was created inside the hidden folder.

- **Timestamp:** 2025-05-19T21:20:23.1352634Z
- **Event:** The file runme.ps1 was created inside the hidden secret_stuff folder by powershell_ise.exe.
- **Action:** Suspicious script file placed in a hidden directory, which may indicate preparation for malicious activity.
- **File Path:** C:\Users\huy\Documents\secret_stuff\runme.ps1

### 3. The PowerShell script runme.ps1 was executed with bypassed execution policy.

- **Timestamp:** 2025-05-19T21:20:32.0000000Z
- **Event:** The script runme.ps1 located in the hidden folder was executed using powershell.exe with the -ExecutionPolicy Bypass flag.
- **Action:** Suspicious script execution from a hidden folder, indicative of potential malicious or unauthorized activity.
- **Command:** powershell.exe -ExecutionPolicy Bypass -File C:\Users\huy\Documents\secret_stuff\runme.ps1
---

## Summary

This threat hunt identified suspicious activity involving the creation and concealment of a hidden folder named secret_stuff within a user’s Documents directory, followed by the placement and execution of a PowerShell script inside that folder. The use of the attrib +h command to hide the folder combined with the execution of a script using powershell.exe with an execution policy bypass strongly suggests an attempt to evade standard detection and potentially execute malicious code. These behaviors align with known adversary techniques to hide payloads and run unauthorized scripts in Windows environments.

The investigation leveraged Microsoft Defender for Endpoint telemetry and Kusto Query Language (KQL) queries to detect these indicators of compromise (IoCs). The findings emphasize the importance of monitoring hidden file system objects and unusual script executions originating from concealed locations as part of an effective security posture.

---

## Response Taken

1. Immediate Containment:
The affected user account and endpoint device were isolated from the network to prevent potential lateral movement or further execution of suspicious scripts.

2. Further Investigation:
Additional analysis was conducted to identify any other hidden directories or scripts created in similar paths across the environment, expanding the search to detect possible related malicious activity.

3. Malware and Script Analysis:
The suspicious PowerShell script runme.ps1 was extracted and analyzed in a sandbox environment to determine its intent, payload, and any associated indicators of compromise.

4. Remediation:
The hidden folder and associated files were deleted after confirming malicious intent. The system was scanned with endpoint protection tools to remove any residual threats.

5. Policy and Detection Enhancements:
Security monitoring rules were updated to alert on the creation of hidden folders, usage of the attrib command to set hidden attributes, and execution of scripts from hidden directories. Endpoint Detection and Response (EDR) configurations were fine-tuned to detect and block script execution with bypassed policies.

6. User Awareness:
The affected user was informed about the incident and educated on security best practices regarding suspicious file handling and script execution to prevent recurrence.


---
