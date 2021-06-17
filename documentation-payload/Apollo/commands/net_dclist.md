+++
title = "net_dclist"
chapter = false
weight = 103
hidden = true
+++

## Summary
Collect information on domain controllers from the current or a specified domain

### Arguments (Positional)
#### domain (optional)
Specify the domain to collect domain controller information from. This will default to the current domain if one is not supplied.

## Usage
```
net_dclist [domain]
```
Example
```
net_dclist lab.local
```
![net_dclist](../images/net_dclist.png)


## MITRE ATT&CK Mapping

- T1590

## Detailed Summary
The `net_dclist` command uses `System.DirectoryServices.ActiveDirectory.DomainController.FindAll` method to collect information about domain controllers in a specified domain. This information includes the DC's computer name, IP address, domain, forest, OS version and whether it is a global catalog.

Below shows the output of running the command. If the domain controller is a global catalog, a book will be displayed next to the computername.