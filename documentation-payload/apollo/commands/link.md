+++
title = "link"
chapter = false
weight = 103
hidden = true
+++

## Summary
Link or re-link an agent to callback.

### Arguments (Popup)
#### Host
Select the host running an agent to connect too.

#### Payload
Select the payload template that is associated with the running payload on the remote host. This determines what named pipe to establish connection with.

## Usage
```
link
```
In pop up menu
```
Host: [drop down list of hosts]
Payload: [drop down list of payloads] 
```

Exmaple
```
link
```
In pop up menu
```
Host: client01.shire.local
Payload: Apollo_SMB.exe
```


## MITRE ATT&CK Mapping

- T1570
- T1572
- T1021

## Detailed Summary
The `link` command connects agents to other callbacks for peer to peer communication. This can be used to connect new agents or re-link to un-linked agents. 
