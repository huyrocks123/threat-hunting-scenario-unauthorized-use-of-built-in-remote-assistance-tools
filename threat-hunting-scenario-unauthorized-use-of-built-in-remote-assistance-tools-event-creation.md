# Threat Event (Unauthorized Use of Built-in Remote Assistance Tools)
**Suspicious Use of msra.exe (Microsoft Remote Assistance)**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Opened msra.exe (Windows Remote Assistance tool) manually using the Run window.
2. Opened command prompt and ran:
```kql
msra.exe /offerra PC1234
msra.exe /offerra John-PC
msra.exe /offerra WIN-TEST01
msra.exe /offerra Desktop-Dev01
```
3. Created a text file named remote-control-notes.txt on the desktop, jotting down targets and session times.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Detect execution of msra.exe and the /offerra flag. |


| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents |
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**|	Detect creation of the file remote-control-notes.txt. |

---

## Related Queries:
```kql
// Any msra.exe executions (including from GUI)
DeviceProcessEvents
| where FileName == "msra.exe"
| where InitiatingProcessFileName == "explorer.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine

// Suspicious use of msra.exe with remote assistance
DeviceProcessEvents
| where FileName == "msra.exe"
| where ProcessCommandLine contains "/offerra"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect creation of suspicious notes file
DeviceFileEvents
| where FileName contains "remote-control-notes.txt"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
```
---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: May 19, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | May 19, 2025  | Huy Tang  
