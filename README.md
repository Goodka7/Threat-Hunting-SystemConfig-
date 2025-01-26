<img width="400" src="https://github.com/user-attachments/assets/a3057464-cfa8-47fb-ad30-4c32c61e4c7d"/>

# Threat Hunt Report: Unauthorized System Configuration Changes
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting-SystemConfig-/blob/main/resources/Threat-Hunt-Event(SystemConfig).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

##  Scenario

Management is concerned about potential tampering with critical system configurations that could weaken security defenses or enable malicious activities. Recent security logs have revealed irregular modifications to registry keys and firewall rules, including attempts to disable Windows Defender and change system policies. The goal is to detect suspicious system configuration changes, such as unauthorized registry edits, firewall modifications, or service disruptions, and analyze any related security incidents. If any suspicious activity is identified, notify management for further investigation.

### High-Level PowerShell Discovery Plan

- **Check `DeviceRegistryEvents`** for unauthorized registry changes, particularly those targeting security-related keys (e.g., Disabled Windows Defender, Modified UAC settings, Changed system policies)  
- **Check `DeviceProcessEvents`** to look for suspicious processes used to execute configuration changes (e.g., regedit.exe, powershell.exe, cmd.exe, sc.exe)  
- **Check `DeviceNetworkEvents`** to identify unusual network activity following system configuration changes.  
- **Check `DeviceEvents`** for service modifications, particularly attempts to stop or disable critical security-related services (e.g., Windows Defender Antivirus)   
 
---

## Steps Taken

### 1. Searched the `DeviceRegistryEvents` Table

Searched for any registry that action type held the value "RegistryValueSet" or "RegistryValueDeleted".

The dataset reveals registry activity originating from the device "thscenariovm" that aligns with concerns about tampering with critical system configurations. On **Jan 26, 2025, at 1:03:30 PM**, a command executed by `cmd.exe` deleted cached standalone update binaries, targeting the key `HKEY_CURRENT_USER\S-1-5-21-2408751320-1394585240-3964484208-500\SOFTWARE\Microsoft\WindowsUpdate` and altering the value `Delete Cached Standalone Update Binary`. This activity suggests potential interference with the system update mechanism. 

Additionally, an update to the `OneDrive` path on **Jan 26, 2025, at 1:03:10 PM** indicates possible tampering with user-specific configurations. These events warrant further investigation to assess whether they represent unauthorized modifications aimed at weakening system defenses or enabling malicious activities.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where DeviceName == "thscenariovm"
| where ActionType in ("RegistryValueSet", "RegistryValueDeleted")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/dca4eca9-ae52-4e44-bb01-596a9a4e80af">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any process events that held "regedit.exe", "powershell.exe", "cmd.exe", or "sc.exe" in the FileName.

The dataset reveals process activity on the device "thscenariovm" involving commands executed by `cmd.exe` and `powershell.exe`, both of which are commonly used for system configuration changes. On **Jan 26, 2025, at 12:49:08 PM**, a command initiated by `runcommandextension.exe` executed `cmd.exe` with a PowerShell script using the `-ExecutionPolicy Unrestricted` flag. This was followed by similar commands at **1:16:13 PM** and **1:24:47 PM**, suggesting repeated attempts to run scripts with unrestricted policies. Additionally, on **Jan 26, 2025, at 12:41:03 PM**, a command was initiated by `powershell.exe` to execute another PowerShell script with potentially unsafe parameters, such as `-ExecutionPolicy Bypass`. 

These activities highlight the use of elevated PowerShell and command-line operations, which align with potential tampering with critical configurations or the execution of unauthorized scripts. The repeated usage of `-ExecutionPolicy Unrestricted` and `-Bypass` flags warrants further investigation to determine whether these actions were authorized or indicative of malicious intent.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "thscenariovm"
| where FileName in~ ("regedit.exe", "powershell.exe", "cmd.exe", "sc.exe")
| where ProcessCommandLine has_any ("Set-", "Disable", "Enable", "-ExecutionPolicy", "-NoProfile", "-NonInteractive", "bypass", "New-ItemProperty")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/926684fe-1507-4af8-abc5-3c8d466f3de2">
```

---

### 3. Searched the `DeviceNetworksEvents` Table

Searched for any network activity that may give clues to malicious acts.

The dataset reveals significant network activity originating from the device "thscenariovm." On **Jan 26, 2025, at 12:49:12 PM**, `powershell.exe` initiated multiple successful connections to `raw.githubusercontent.com` (IP address `185.199.111.133`) over HTTPS (port 443). Similarly, another connection to `raw.githubusercontent.com` (IP address `185.199.110.133`) was observed at **1:16:15 PM**, also using `powershell.exe`. These domains are known to host scripts and files, suggesting potential script download or execution activity. 

The use of `powershell.exe` for network communication and repeated connections to script-hosting domains aligns with concerns about unauthorized activities and tampering with system configurations. These events warrant further investigation to assess whether they involve the execution of malicious scripts or unauthorized system changes.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "thscenariovm"
| where RemotePort in (3389, 445, 135) or RemoteUrl has_any (".onion", "raw.githubusercontent.com", "unknown-domain")
| where ActionType in ("ConnectionSuccess", "ConnectionFailed")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/58865235-2a2c-4c44-ab32-dd0c0b933b23">

---

### 4. Searched the `DeviceProcessEvents` Table

Further searched for unusual changes, particularly with the word "administrators" in the command line.

The dataset reveals activity related to the addition of a user to the `Administrators` group on the device "thscenariovm." On **Jan 26, 2025, at 1:08:42 PM**, the command `"net.exe" localgroup administrators NewAdminAccount /add` was executed by the user `labuser`, successfully adding the account `NewAdminAccount` to the `Administrators` group. 

Additionally, a second command, `"net.exe" localgroup administrators`, was executed at **Jan 26, 2025, at 1:09:56 PM**, listing the members of the `Administrators` group, which confirms the account was successfully added.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thscenariovm"
| where ProcessCommandLine has "administrators"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/aed5e71a-8641-4b5b-bf64-119cc0f9a010">

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
