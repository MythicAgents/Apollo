+++
title = "reg_write_value"
chapter = false
weight = 103
hidden = true
+++

## Summary
Write a new string or integer value to the specified Value Name that's within the specified Registry Key.

### Arguments (Popup or Positional)

#### Registry Key
The registry key to retrieve subkeys for. This  must be in the format of `HKLM:\SYSTEM\Setup`, where `HKLM` can be any of the following values:

- `HKLM`
- `HKCU`
- `HKCR`

#### Value Name
The registry value name to retrieve the value of. Leave blank to retrieve the default value.

#### New Value
The new value to store in the designated Value Name. If this is an integer, a DWORD will be written. Otherwise, this will be a string.

## Usage
Set the value of `OsLoaderPath` from the `HKLM:\SYSTEM\Setup` registry key to `\HardDisk4\`.
```
reg_write_value HKLM:\SYSTEM\Setup OsLoaderPath \HardDisk4\
```

Or, using the modal pop up menu...
```
reg_write_value
```
Then enter the key to interrogate.
```
Registry Key: [key name]
Value Name: [value name]
New Value: [new value]
```

## MITRE ATT&CK Mapping

- T1547
- T1037
- T1546
- T1574
- T1112
- T1003

>A Registry Write artifact is generated from this command.