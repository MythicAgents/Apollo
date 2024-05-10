+++
title = "ticket_cache_list"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: WindowsAPIInvoke
{{% /notice %}}

## Summary
list information about all loaded tickets in the current active logon session. This uses lsa apis to return all relevant information about the tickets in the current session. 
If ran from an elevated context this also gets information on tickets in all sessions. 


### Arguments


#### luid
Optional argument to filter the tickets in the agents store to ones matching a specified luid.



## Usage
```
ticket_cache_list -luid [luidValue]
```

Example
```
ticket_cache_list -luid [luidValue]
```

## MITRE ATT&CK Mapping
- T1550