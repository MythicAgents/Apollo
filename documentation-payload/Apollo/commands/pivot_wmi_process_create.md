+++
title = "pivot_wmi_process_create"
chapter = false
weight = 103
hidden = true
+++

{{% notice warning %}}
This uses .NET's builtin WMI APIs that do not respect token impersonation. Do not use this command unless you're already in a context which has access to the remote machine.
{{% /notice %}}

## Summary
Perform lateral movement via WMI process creation.

### Arguments (Popup)
#### computer
The remote host to perform lateral movement too.

#### credential
The credential to execute the WMI command as. If not specified, this will use the current thread's access token.

#### remote_path
The remote file path to save the payload too. This will default to saving the file in `C:\Users\Public`

#### template
The payload tenplate to generate the payload from.

## Usage
```
pivot_wmi_process_create
```

In the pop up menu
```
computer: [remote host]
credential: [credential]
remote_path: [path]
template: [payload]
```

Example
```
pivot_wmi_process_create
```

In the pop up menu
```
computer: client01.shire.local
credential: john.smith - Password123
remote_path: C:\Windows\Temp\
template: Apollo - HTTP,SMBServer
```

## Detailed Summary
The `pivot_wmi_process_create` uses SMB and WMI for remote file copy and process execution to perform lateral movement. The payload selected is written to the target host with a random GUID filename over SMB using the `System.IO.File.WriteAllBytes` method. Execution of the payload is then achieved through the use of the `Win32_process` method of the `System.Management` class.
