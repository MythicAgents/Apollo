+++
title = "ticket_cache_extract"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: WindowsAPIInvoke
{{% /notice %}}

## Summary
Extract the specified ticket(s) from the current logon session, this uses LSA APIs to extract a ticket from the active logon session on the host.
This includes all details and a base64 encoded copy of the ticket.
If ran from an elevated context this also can get a ticket from any session. 


### Arguments


#### luid
Optional argument to extract a ticket from the cache of a different logon session, must be elevated.

#### Service
The name of the service to taget for example krbtgt for tgt, or one of the various service ticket types (ex. cifs, host, ldap, etc.)

## Usage
```
ticket_cache_extract -luid [luidValue] -service [service]
```

Example
```
ticket_cache_extract -luid 0xabcd -service cifs
ticket_cache_extract -service krbtgt
```

## MITRE ATT&CK Mapping
- T1550