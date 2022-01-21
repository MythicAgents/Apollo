+++
title = "net_localgroup_member"
chapter = false
weight = 103
hidden = false
+++

## Summary
Collect membership of local groups on a specified computer.

### Arguments

#### Group

Name of group to query for membership.

#### Computer (optional)

Specify the computer to collect group information from. This will default to the localhost if one is not supplied.

## Usage
```
net_localgroup_member [computer] [group]
```

![net_localgroup_member command](../images/net_localgroup_member.png)


## MITRE ATT&CK Mapping

- T1590
- T1069

## Detailed Summary
The `net_localgroup_member` command uses `NetLocalGroupGetMembers` Windows API to collect information about local group membership on a specified host. This information includes the member's name, group name, SID, if the member is a group and what computer it was collected from.