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
- **Check `DeviceProcessEvents`** for group policy modifications (e.g., Administrators group)   
 
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

### 1. Registry Modification - Disable UAC
- **Time:** `1:03:30 PM, January 26, 2025`
- **Event:** The user "labuser" executed a command using `cmd.exe` that disabled User Account Control (UAC) by modifying the registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
- **Action:** Registry value modification detected.
- **Command:** `Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0`
- **Initiating Process:** `cmd.exe`

### 2. Windows Defender Disabled
- **Time:** `1:03:10 PM, January 26, 2025`
- **Event:** Windows Defender real-time monitoring was disabled via `powershell.exe` using the `Set-MpPreference` command.
- **Action:** Process executed to modify security settings.
- **Command:** `Set-MpPreference -DisableRealtimeMonitoring $true`

### 3. Administrators Group Modified
- **Time:** `1:08:42 PM, January 26, 2025`
- **Event:** The user "labuser" executed a command using `net.exe` to add the account `NewAdminAccount` to the `Administrators` group.
- **Action:** Process detected adding a new administrator account.
- **Command:** `net.exe localgroup administrators NewAdminAccount /add`
- **Initiating Process:** `net.exe`
- **Group:** `Administrators`
- **Account Name:** `NewAdminAccount`

### 4. Registry Modification - Cached Updates Deleted
- **Time:** `1:03:30 PM, January 26, 2025`
- **Event:** A registry key modification was made to delete cached standalone update binaries from `HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsUpdate`.
- **Action:** Registry value deleted.
- **Command:** `cmd.exe /q /c del /q "C:\Users\labuser\Updates\Standalone"`
- **Initiating Process:** `cmd.exe`
- **Registry Key:** `HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsUpdate`
- **Registry Value Name:** `Delete Cached Standalone Update Binary`

---

## Summary

The user "labuser" on the device "thscenariovm" performed a series of actions that align with tampering with critical system configurations. Key findings include the disabling of UAC and Windows Defender, as well as the addition of a new local administrator account to the `Administrators` group. These actions were executed using `cmd.exe` and `powershell.exe`, indicating deliberate attempts to weaken the system's security posture. Additionally, cached update binaries were deleted, which could disrupt system updates and prevent the application of security patches. The registry changes and process executions observed suggest potential malicious intent and warrant immediate investigation to assess the impact and prevent further exploitation.

---

## Response Taken

Unauthorized System Configuration activity was confirmed on the endpoint `thscenariovm` by the user `labuser`. The device was immediately isolated to prevent further potential misuse, and the user's direct manager was notified for follow-up investigation, remediation and potential disciplinary action.

---
