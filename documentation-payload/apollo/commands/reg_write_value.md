+++
title = "reg_write_value"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Registry Write
{{% /notice %}}

## Summary
Write a new string or integer value to the specified Value Name that's within the specified Registry Key.

### Arguments

#### Hive
The registry hive in which the `Key` lives. Must be one of:

- HKLM
- HKCU
- HKU
- HKCR
- HKCC

#### Key
The registry key to write to. Default: `\`

#### Name (optional)
The name of the value to which you wish to write the new value to. Default will write to the `(Default)` value.

#### Value (optional)
The new value to store in the designated Name. If this is an integer, a DWORD will be written. Otherwise, this will be a string.

## Usage
Set the value of `OsLoaderPath` from the `HKLM:\SYSTEM\Setup` registry key to `\HardDisk4\`.
```
reg_write_value -Hive HKLM -Key SYSTEM\\Setup -Name OsLoaderPath -Value \\HardDisk4\\
```

## MITRE ATT&CK Mapping

- T1547
- T1037
- T1546
- T1574
- T1112
- T1003
