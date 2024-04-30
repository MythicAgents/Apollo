+++
title = "ticket_cache_purge"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated:  WindowsAPIInvoke
{{% /notice %}}

## Summary
Remove the specified ticket(s) from the current logon session, this uses LSA APIs to delete tickets from the active logon session on the host.


### Arguments


#### serviceName 
the name of the service to remove, needs to include the domain name, is required if -all flag is not present

#### All (Optional)
Argument flag to remove all tickets from the current logon session

#### luid (Optional)
Optional argument to remove a ticket from the cache of a different logon session, must be elevated.


## Usage
```
ticket_cache_purge -luid [luidValue] -serviceName  [serviceName] -All
```

Example
```
ticket_cache_purge -serviceName  [serviceName]
ticket_cache_purge -All
ticket_cache_purge -luid 0xabcd123 -serviceName  [serviceName]
ticket_cache_purge -luid 0xabcd123  -All
```

## MITRE ATT&CK Mapping
- T1550