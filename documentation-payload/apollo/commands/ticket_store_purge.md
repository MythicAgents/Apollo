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


#### Base64ticket 
The base64 ticket value of the ticket to remove from the store
This value is optional when the all flag is used

#### All (Optional)
Argument flag to remove all tickets from Apollo's ticket store



## Usage
```
ticket_store_purge -base64ticket [ticketValue] -all
```

Example
```
ticket_store_purge -base64ticket [ticketValue]
ticket_store_purge -all
```

## MITRE ATT&CK Mapping

- T1550