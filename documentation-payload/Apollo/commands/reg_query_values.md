+++
title = "reg_query_values"
chapter = false
weight = 103
hidden = true
+++

## Summary
Query value names of a specified registry key.

### Arguments (Popup or Positional)
#### Registry Key
The registry key to retrieve values for. This  must be in the format of `HKLM:\SYSTEM\Setup`, where `HKLM` can be any of the following values:

- `HKLM`
- `HKCU`
- `HKCR`

## Usage
```
reg_query_values HKLM:\SYSTEM\Setup
```

Or, using the modal pop up menu...
```
reg_query_values
```
Then enter the key to interrogate.
```
Registry Key: [key name]
```

![query](../images/reg_query_values.png)