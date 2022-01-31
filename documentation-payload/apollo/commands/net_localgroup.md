+++
title = "net_localgroup"
chapter = false
weight = 103
hidden = false
+++

# net_localgroup

## Summary
Collect information on local groups for a specified computer.

### Arguments (Positional)
#### Computer (optional)
Specify the computer to collect group information from. This will default to the localhost if one is not supplied.

## Usage
```
net_localgroup [computer]
```
Example
```
net_localgroup client01.lab.local
```

![net_localgroup](../images/net_localgroup.png)


## MITRE ATT&CK Mapping

- T1590
- T1069