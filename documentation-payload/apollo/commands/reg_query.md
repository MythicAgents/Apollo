+++
title = "reg_query"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Registry Read
{{% /notice %}}

## Summary
Query subkeys of a specified registry key.

### Arguments

![subkeys](../images/reg_query.png)

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

![subkeys](../images/reg_query_disp.png)

## MITRE ATT&CK Mapping

- T1012