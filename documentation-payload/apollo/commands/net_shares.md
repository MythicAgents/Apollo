+++
title = "net_shares"
chapter = false
weight = 103
hidden = true
+++

## Summary
Collect information on network shares for a specified host.

### Arguments (Positional)
#### computer
Specify the computer to collect network shares information from.

## Usage
```
net_shares [computer]
```
Example
```
net_shares client01.lab.local
```

![net_shares](../images/net_shares.png)


## MITRE ATT&CK Mapping

- T1590
- T1069

## Detailed Summary
The `net_shares` command uses `NetShareEnum` Windows API to collect information about network shares on a specified host. This information includes the share's name, comments, type of share and what computer it was collected from.

If the computer's share is accessible, it'll be listed alongside an open folder icon. Otherwise, a lock will be displayed next to it.