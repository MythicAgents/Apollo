+++
title = "reg_query_subkeys"
chapter = false
weight = 103
hidden = true
+++

## Summary
Query subkeys of a specified registry key.

### Arguments (Positional or Popup)
#### Registry Key
The registry key to retrieve subkeys for. This  must be in the format of `HKLM:\SYSTEM\Setup`, where `HKLM` can be any of the following values:

- `HKLM`
- `HKCU`
- `HKCR`

## Usage
```
reg_query_subkeys HKLM:\SYSTEM\Setup
```

Or, using the modal pop up menu...
```
reg_query_subkeys
```
Then enter the key to interrogate.
```
Registry Key: [key name]
```

## MITRE ATT&CK Mapping

- T1012

## Artifacts

- Registry Read

![subkeys](../images/reg_query_subkeys.png)