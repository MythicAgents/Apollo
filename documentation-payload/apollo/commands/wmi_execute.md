+++
title = "wmi_execute"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: WindowsAPIInvoke
{{% /notice %}}

## Summary
Use WMI to execute a command on the local or specified remote system, can also be given optional credentials to impersonate a different user.
Note it will not return output from the executed command, this is due to how wmi is handled by windows.


### Arguments


#### command
Should be the full path and arguments of the process to execute
#### host
Computer to execute the command on. If empty, the current computer
#### username
username of the account to execute the wmi process as
#### password
plaintext password of the account
#### domain
domain name for the account


## Usage
```
wmi_execute -command [Value] -host [Value] -username [Value] -password [Value] -domain [Value]
```

Example
```
wmi_execute -command "c:\windows\tasks\apollo.exe" -host dc01.domain.local -username admin -password mypassword -domain domain.local 
```

## MITRE ATT&CK Mapping
-