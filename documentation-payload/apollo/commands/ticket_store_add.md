+++
title = "ticket_store_add"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated:  WindowsAPIInvoke
{{% /notice %}}

## Summary
Add a new ticket to the agents internal ticket store. The supplied ticket should be a base64 encoded ticket. 
The ticket will be loaded into a temp logon session and extracted to repopulate all relevant information. 


### Arguments


#### B64ticket 
The base64 ticket value of the ticket to add to the store



## Usage
```
ticket_store_add -base64ticket [ticketValue]
```

Example
```
ticket_store_add -base64ticket [ticketValue]
```

## MITRE ATT&CK Mapping

- T1550