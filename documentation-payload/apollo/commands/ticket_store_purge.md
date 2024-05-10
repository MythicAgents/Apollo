+++
title = "ticket_store_purge"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: 
{{% /notice %}}

## Summary
Remove the specified ticket(s) from the agents internal ticket store


### Arguments


#### serviceName 
the name of the service to remove, needs to include the domain name, not required if -all flag is present

#### All (Optional)
Argument flag to remove all tickets from Apollo's ticket store



## Usage
```
ticket_store_purge -serviceName  [serviceName] -all
```

Example
```
ticket_store_purge -serviceName  ldap/machineName.DomainName.local/domainName.local@DomainName.local
ticket_store_purge -serviceName  cifs/machineName@DomainName.local
ticket_store_purge -all
```

## MITRE ATT&CK Mapping
- T1550