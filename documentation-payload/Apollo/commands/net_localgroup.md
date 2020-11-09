+++
title = "net_localgroup"
chapter = false
weight = 103
hidden = false
+++

# net_localgroup

## Summary
Collect information on local groups for a specified computer.

### Arguments (positional)
#### computer
Specify the computer to collect group information from. This will default to the localhost if one is not supplied.

## Usage
```
net_localgroup [computer]
```
Example
```
net_localgroup client01.shire.local
```

## Detailed Summary
The `net_localgroup` command uses `NetLocalGroupEnum` Windows API to collect information about local groups on a specified host. This information includes the group's name, SID, comments and computer it was collected from.

![net_localgroup](../images/net_localgroup.png)