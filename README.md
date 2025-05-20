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

### 3. Tracked Creation and Modification of remote-control-notes.txt

To detect activity related to potential operational planning or session tracking, I queried for file system events involving a file named remote-control-notes.txt. 

At 2025-05-20T00:17:02.8202038Z, a file on the desktop was renamed to remote-control-notes.txt.txt by explorer.exe. Seconds later, at 2025-05-20T00:17:03.0220822Z, a shortcut file remote-control-notes.txt.lnk was created in the Recent folder, confirming that the document had been accessed or opened. At 2025-05-20T00:17:14.0202785Z, the file was modified using notepad.exe, likely as the attacker updated their operational notes. 

**Query used to locate event:**
```kql
DeviceFileEvents
| where FileName contains "remote-control-notes.txt"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
```

<img width="1420" alt="Screenshot 2025-05-19 at 9 26 09 PM" src="https://github.com/user-attachments/assets/d04d2226-0037-4fe8-a2e9-9ae5cd8eb451" />

## Chronological Event Timeline 

### 1. msra.exe launched manually via GUI

- **Timestamp:** 2025-05-20T00:13:43.0482142Z
- **Event:** The Remote Assistance tool (msra.exe) was launched by the user "huy" on device "huy" through the graphical interface (explorer.exe).
- **Action:** Indicates manual execution, likely via Start Menu or Run dialog, to probe or prepare for further activity.
- **Command Source:** explorer.exe → msra.exe

### 2. Unsolicited Remote Assistance initiated to target: PC1234

- **Timestamp:** 2025-05-20T00:15:19.0569006Z
- **Event:** User "huy" attempted to initiate an unsolicited Remote Assistance session to host "PC1234" using the /offerra flag.
- **Action:** First sign of suspicious lateral movement using msra.exe to connect to another internal machine.
- **Command:** msra.exe /offerra PC1234

### 3. Unsolicited Remote Assistance initiated to target: John-PC

- **Timestamp:** 2025-05-20T00:15:51.8459403Z
- **Event:** A second remote session attempt was made by user "huy" to the host "John-PC".
- **Action:** Repeated unauthorized access attempts suggesting probing or lateral movement.
- **Command:** msra.exe /offerra John-PC

### 4. Unsolicited Remote Assistance initiated to target: WIN-TEST01

- **Timestamp:** 2025-05-20T00:16:08.1419023Z
- **Event:** A third Remote Assistance session was launched targeting "WIN-TEST01".
- **Action:** Indicates ongoing effort to compromise multiple internal systems.
- **Command:** msra.exe /offerra WIN-TEST01

### 5. Unsolicited Remote Assistance initiated to target: Desktop-Dev01

- **Timestamp:** 2025-05-20T00:16:25.5630260Z
- **Event:** Final known Remote Assistance attempt was made to "Desktop-Dev01".
- **Action:** Reinforces pattern of unsolicited remote session initiation, likely without user consent.
- **Command:** msra.exe /offerra Desktop-Dev01

### 6. Operational notes saved in remote-control-notes.txt

- **Timestamp:** 2025-05-20T00:17:14.0202785Z
- **Event:** A file named remote-control-notes.txt was created on the user's Desktop to document session details.
- **Action:** Indicates attacker was tracking operations or targets, which could be useful for operational planning or persistence.
- **File Path:** C:\Users\huy\Desktop\remote-control-notes.txt

---

## Summary

This threat hunt uncovered suspicious use of Microsoft's built-in Remote Assistance tool (msra.exe) in a manner consistent with unauthorized remote session initiation and lateral movement within a network. The attacker, operating from a single device under the user account "huy," executed multiple instances of msra.exe /offerra targeting internal hosts (e.g., PC1234, John-PC, WIN-TEST01, Desktop-Dev01) — a technique used to initiate unsolicited Remote Assistance sessions.

To maintain operational awareness, the attacker temporarily created and modified a file named remote-control-notes.txt on the desktop, suggesting the tracking of session targets or outcomes. The file was later accessed via the GUI and altered using Notepad, indicating interactive behavior consistent with hands-on-keyboard activity. Evidence of file renaming and shortcut creation further confirmed active interaction with the file. The hunt clearly points to deliberate use of legitimate tools for potentially malicious internal reconnaissance and access.

---

## Response Taken

The findings were escalated to the Security Operations Center (SOC) for containment and further investigation.

The user account "huy" and the associated endpoint "huy" were flagged for immediate review and access restriction.

Microsoft Defender for Endpoint was used to isolate the affected machine from the network to prevent potential spread.

A search was initiated across the environment to identify any additional use of msra.exe /offerra or creation of remote-control-notes.txt on other endpoints.

A detection rule was proposed for alerting on command-line execution of msra.exe with the /offerra flag and rapid creation/deletion of suspiciously named text files on user desktops.

End-user awareness training was recommended to cover risks associated with built-in remote access tools.

---
