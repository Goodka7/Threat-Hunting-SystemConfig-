<img width="300" src="https://github.com/user-attachments/assets/9c09c98f-0e0f-40f4-a921-696b5fd7e44e" alt="Red PowerShell logo"/>

# Threat Hunt Report: Suspicious PowerShell Activity
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting-PowerShell-/blob/main/resources/Threat-Hunt-Event(PowerShell).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

##  Scenario

Management is concerned about potential misuse of PowerShell to execute malicious commands or disable security features. Recent security logs indicate irregular PowerShell execution patterns, including encoded commands and the disabling of security tools. The goal is to detect suspicious PowerShell usage, such as obfuscated scripts or unauthorized execution of system commands, and analyze any related security incidents. If any suspicious activity is identified, notify management for further investigation.

### High-Level PowerShell Discovery Plan

- **Check `DeviceProcessEvents`** for PowerShell processes executed in a suspicious manner (e.g., via`cmd.exe`, `rundll32.exe`).
- **Check `DeviceNetworkEvents`** for any network activity involving suspicious external requests (e.g., file download attempts using `Invoke-WebRequest`).
- **Check `DeviceFileEvents`** any new or suspicious file creations in temporary directories (e.g., `C:\Windows\Temp\FakeMalware`).
- **Check `DeviceRegistryEvents`** for unusual changes, particularly in execution policies or PowerShell-related settings.
---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for any process that had "cmd.exe", "rundll32.exe", "powershell_ise.exe" or "powershell.exe" in the command line. 

The dataset reveals 88 records of process activity on the device "hardmodevm", by user "labuser" predominantly involving powershell.exe (47 instances) and cmd.exe (22 instances as initiating processes). Frequent use of PowerShell commands includes flags like -NoProfile, -NonInteractive, and -ExecutionPolicy Bypass, often triggered via cmd.exe or gc_worker.exe, suggesting possible script automation or suspicious activity. Initiating processes such as WindowsAzureGuestAgent.exe and timestamps concentrated on Jan 25, 2025, further indicate repeated execution patterns. These observations suggest potentially unauthorized or automated operations warranting deeper investigation.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("cmd.exe", "rundll32.exe", "powershell_ise.exe", "powershell.exe")
| where DeviceName == "hardmodevm"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/e5e5fee9-fa90-403b-aed5-4553926bf119">

---

### 2. Searched the `DeviceNetworkEvents` Table

Searched for any connections that contained the commands "Invoke-WebRequest", "-Uri" and "http". 

The dataset reveals network activity originating from "hardmodevm", user "labuser", with notable connections initiated by powershell.exe using commands that include -ExecutionPolicy Bypass. External requests were made to URLs such as raw.githubusercontent.com, associated with IP addresses 185.199.108.133 and 185.199.111.133, both of which are commonly used to host scripts or files. These connections occurred over HTTPS (port 443) and were marked as successful (ConnectionSuccess). The combination of PowerShell usage with potentially suspicious URLs highlights activity that may involve downloading or executing external scripts, warranting further investigation.

**Query used to locate event:**

```kql
DeviceNetworkEvents
| where DeviceName == "hardmodevm"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
      or InitiatingProcessCommandLine contains "-Uri"
      or RemoteUrl has "http"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/926684fe-1507-4af8-abc5-3c8d466f3de2">

---

### 3. Searched the `DeviceFileEvents` Table

Searched for any new or suspicious file creations in temporary directories.

The dataset reveals evidence of the execution of `payload.ps1`, with several temporary files created in the directory `C:\Users\labuser\AppData\Local\Temp\`. Files such as `__PSScriptPolicyTest_xp01hqvv.wby.ps1` were generated during the execution of `powershell.exe` and `powershell_ise.exe`, both of which used the `-ExecutionPolicy Bypass` parameter. These actions are marked as `FileCreated`, confirming that the payload execution resulted in temporary script files being generated. This activity indicates successful script execution with potentially bypassed security policies, warranting further investigation into the impact of these temporary files.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "hardmodevm"
| where FolderPath startswith "C:\\Windows\\Temp\\" or FolderPath contains "\\Temp\\"
| where FileName endswith ".exe" or FileName endswith ".ps1"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/fc3c072b-e1e1-43c7-862c-6dce9f305d5c">

---

### 4. Searched the `DeviceRegistryEvents` Table

Searched for unusual changes, particularly in execution policies or PowerShell-related settings.

The data highlights changes on hardmodevm involving keys related to both PowerShell and general system configurations. Notably, registry keys such as HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates and HKEY_CURRENT_USER\S-1-5-21...WindowsPowerShell\v1.0\powershell.exe were altered, with actions including RegistryValueSet and RegistryKeyCreated. These changes were initiated by processes like svchost.exe and explorer.exe. 

While no direct link to altered execution policies was found, the involvement of PowerShell-related keys and potentially suspicious value modifications like Microsoft Corporation suggests configuration changes that might impact system behavior. These events warrant further review to determine their relationship with recent payload execution and possible security implications.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where DeviceName == "hardmodevm"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated", "RegistryKeyDeleted")
| where RegistryKey contains "PowerShell" 
      or RegistryKey contains "Microsoft"
      or RegistryKey contains "Policies"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueType, RegistryValueData, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/fbce844e-8ebd-40ad-96e0-49d0ddae1ce8">

---

## Chronological Event Timeline

### 1. Process Execution - PowerShell Script Execution

- **Time:** `2:08:23 PM, January 25, 2025`
- **Event:** The user "system" executed `payload.ps1` via `powershell.exe` with the `-ExecutionPolicy Bypass` flag, indicating a bypass of default execution policies.
- **Action:** Process creation detected.
- **Command:** `"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\labuser\AppData\Local\Temp\payload.ps1"`
- **Initiating Process:** `"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File "C:\Users\labuser\AppData\Local\Temp\payload.ps1"`
- **File Path:** `C:\Users\labuser\AppData\Local\Temp\payload.ps1`

### 2. File Creation - Temporary Script

- **Time:** `2:11:46 PM, January 25, 2025`
- **Event:** A temporary PowerShell script was created during execution, named `__PSScriptPolicyTest_bdps4qml.1vq.ps1`.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\AppData\Local\Temp\__PSScriptPolicyTest_bdps4qml.1vq.ps1`
- **Process Command:** `"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\labuser\AppData\Local\Temp\payload.ps1"`

### 3. Process Execution - PowerShell with Encoded Command

- **Time:** `2:37:16 PM, January 25, 2025`
- **Event:** The `powershell.exe` process was executed with a suspicious encoded command by the `system` account.
- **Action:** Process creation detected.
- **Command:** `"powershell.exe" -noninteractive -outputFormat None -EncodedCommand "SQB0ACAAIgBHAEwAIgAA"`
- **Initiating Process:** `"gc_worker.exe" -a WindowsDefenderExploitGuard -b -c`
- **File Path:** Not applicable.

### 4. File Creation - Temporary PowerShell Script

- **Time:** `2:43:18 PM, January 25, 2025`
- **Event:** Another temporary script file, `__PSScriptPolicyTest_xp01hqvv.wby.ps1`, was created during PowerShell execution.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\AppData\Local\Temp\__PSScriptPolicyTest_xp01hqvv.wby.ps1`
- **Process Command:** `"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\labuser\AppData\Local\Temp\payload.ps1"`

### 5. Process Execution - PowerShell via Explorer

- **Time:** `2:43:18 PM, January 25, 2025`
- **Event:** The `powershell.exe` process was executed by `explorer.exe` with no additional parameters.
- **Action:** Process creation detected.
- **Command:** `"PowerShell_ISE.exe"`
- **Initiating Process:** `"explorer.exe"`
- **File Path:** Not applicable.

---

## Summary

The user "labuser" on the device "hardmodevm" executed multiple suspicious PowerShell commands and created temporary files, raising concerns about potential misuse. First, "labuser" initiated the execution of a PowerShell script (`payload.ps1`) with the `-ExecutionPolicy Bypass` flag, bypassing standard security measures. During the execution, temporary script files such as `__PSScriptPolicyTest_bdps4qml.1vq.ps1` and `__PSScriptPolicyTest_xp01hqvv.wby.ps1` were created in the `C:\Windows\Temp` directory. These files indicate automated or obfuscated script activity. Additionally, encoded commands were executed through `powershell.exe`, initiated by `gc_worker.exe`, further suggesting the use of obfuscation techniques to conceal activity. The involvement of elevated accounts like "system" in conjunction with these processes raises further suspicion of privilege escalation or unauthorized operations. The combination of these actions points to potential malicious activity, such as script-based attacks or the disabling of security features, and warrants immediate investigation.

---

## Response Taken

Suspicious PowerShell activity was confirmed on the endpoint `hardmodevm` by the user `labuser`. The device was immediately isolated to prevent further potential misuse, and the user's direct manager was notified for follow-up investigation and potential disciplinary action.

---
