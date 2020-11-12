+++
title = "link"
chapter = false
weight = 103
hidden = true
+++

{{% notice warning %}}
SMB is currently defunct. This command will not successfully stage or reconnect to an SMB agent until this profile is fixed.
{{% /notice %}}

## Summary
Link or re-link an agent to callback.

### Arguments (Popup)
#### Host
Select the host running an agent to connect too.

#### Payload
Select the payload template that is associated with the running payload on the remote host. This determines what named pipe to establish connection with.

#### C2 profile
Select the C2 profile in use by the agent. Can only be SMB at this time.

## Usage
```
link
```
In pop up menu
```
Host: [drop down list of hosts]
Payload: [drop down list of payloads] 
C2 Profile: [drop down list of profiles]
```

Exmaple
```
link
```
In pop up menu
```
Host: client01.shire.local
Payload: Apollo
C2 Profile: SMBServer
```

## Detailed Summary
The `link` command connects agents to other callbacks for peer to peer communication. This can be used to connect new agents or re-link to un-linked agents. 
