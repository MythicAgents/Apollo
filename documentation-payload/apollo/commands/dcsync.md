+++
title = "dcsync"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Create, Process Inject, Process Kill
{{% /notice %}}

## Summary
Use mimikatz's `lsadump::dcsync` module to retrieve a user's kerberos keys from a Domain Controller.

### Arguments
#### Domain
Domain to query information from.

#### User (Optional)
Username to sync kerberos keys for. Default is all users.

#### DC (Optional)
Domain controller to sync credential material from.

## Usage
```
dcsync -Domain domain.local [-User username -DC dc.domain.local]
```

Example
```
dcsync -Domain contoso.local -User djhohnstein -DC 10.120.30.204
dcsync -Domain contoso.local
```


## MITRE ATT&CK Mapping

- T1003.006

### Resrouces
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
