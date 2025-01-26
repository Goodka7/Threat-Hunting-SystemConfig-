# Threat Event (Suspicious System Configuration Changes)
**Unauthorized Changes to System Configurations**

## Steps the "Bad Actor" Took Create Logs and IoCs:
1. Disable Windows Defender using PowerShell: `Set-MpPreference -DisableRealtimeMonitoring $true`
2. Modify UAC settings in the registry: `Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0`
3. Disable automatic updates by creating a registry key: `New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -PropertyType DWORD`
4. Create a new local administrator account: `net user NewAdminAccount Password123! /add && net localgroup administrators NewAdminAccount /add`
5. Enable Remote Desktop settings: `Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0`
6. Add a firewall rule to allow inbound traffic on port 3389: `New-NetFirewallRule -DisplayName "Simulate RDP Rule" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow`

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents                                                            |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Used to detect any PowerShell or command-line activities related to system configuration changes (e.g., disabling Defender, enabling RDP). |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceRegistryEvents                                                           |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table |
| **Purpose**| Used to detect suspicious registry modifications such as changes to security settings, firewall rules, or other configuration changes. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents                                                              |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**| Used to detect the installation of unauthorized software or the creation of new accounts. |

---

## Related Queries:
```kql
// Detect PowerShell commands that modify system configurations (e.g., disabling Defender)
DeviceProcessEvents
| where FileName == "powershell.exe" and ProcessCommandLine contains "Set-MpPreference"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

// Detect RDP enabling via command line
DeviceProcessEvents
| where FileName == "cmd.exe" and ProcessCommandLine contains "New-NetFirewallRule"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

// Detect registry changes to critical security settings (e.g., disabling Defender)
DeviceRegistryEvents
| where RegistryKey in~ ["HKLM\\SOFTWARE\\Microsoft\\Windows Defender", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies"]
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData

// Detect the creation of new local admin accounts or changes to existing ones
DeviceFileEvents
| where FileName has "net.exe" and ProcessCommandLine contains "user" and ProcessCommandLine contains "admin"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// Detect installation of unauthorized software (e.g., persistence tool)
DeviceFileEvents
| where FileName in~ ["malicious_tool.exe", "unauthorized_software.exe"]
| project Timestamp, DeviceName, ActionType, FileName
```

---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47/
- **Date**: January 24, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**
