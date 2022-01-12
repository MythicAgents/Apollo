+++
title = "reg_query_subkeys"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
Artifacts Generated: Registry Read
{{% /notice %}}

## Summary
Query subkeys of a specified registry key.

### Arguments
#### Hive
The registry key to retrieve subkeys for. This  must be in the format of `HKLM:\SYSTEM\Setup`, where `HKLM` can be any of the following values:

- HKLM
- HKCU
- HKU
- HKCR
- HKCC

#### Key (optional)
Registry key to query in the Hive for.

## Usage
```
reg_query -Hive HKLM -Key System\\Setup
```

## MITRE ATT&CK Mapping

- T1012

![subkeys](../images/reg_query.png)