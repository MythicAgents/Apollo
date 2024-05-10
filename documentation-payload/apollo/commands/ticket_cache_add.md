+++
title = "ticket_cache_add"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated:  WindowsAPIInvoke
{{% /notice %}}

## Summary
Add the specified ticket(s) into the current logon session, this uses LSA APIs to load tickets into the active logon session on the host.


### Arguments


#### b64ticket
the base64 ticket to add to the store




## Usage
```
ticket_cache_add -b64ticket [Value]
```

Example
```
ticket_cache_add -b64ticket [Value]
```

## MITRE ATT&CK Mapping
- T1550