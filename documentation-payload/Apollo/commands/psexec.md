+++
title = "psexec"
chapter = false
weight = 103
hidden = false
+++

## Summary
Launch an agent on a remote host using a new service.

### Arguments (modal popup)
#### computer (required)
Remote host to laterally move too.

#### template (required)
The payload template to generate a payload for. This template must be compatible with the `service_wrapper` wrapper payload.

#### display_name
Display name of the service to be displayed to end user. Defaults to "Apollo Service: NEWLY-GENERATED-UUID4-GUID"

#### remote_path
Path on remote host to write the payload file. Defaults to "C:\Users\Public\Apollo-NEWLY-GENERATED-UUID4-GUID.exe"

#### service_name
Name of the service to be created. Defaults to "ApolloService-NEWLY-GENERATED-UUID4-GUID"

## Usage
```
psexec
```
In the pop up menu
```
computer: [target computer]
display_name: [visible service name]
remote_path: [path for payload]
service_name: [name of service]
template: [payload]
```

Example
```
psexec
```
In the pop up menu
```
computer: client01.shire.local
display_name: UpdateChecker
remote_path: C:\Windows\Temp\
service_name: updateChecker
template: Apollo - HTTP,SMBServer
```

## Detailed Summary
The `psexec` command uses a payload and service on a remote host for lateral movement. This payload is created by using `donut` to turn a C# agent into shellcode, then embedded this as a resource in a C# service excutable. This executable will simply load the shellcode and execute it in the current process. The agent will copy this payload to the specified path (`C:\Users\Public` by default) on the target host over SMB. Using the Windows Service Control Manager, the agent will then create a new service on the remote host with the payload as the service binary. The display name and service name can be customized or left as default (`ApolloService-[GUID]`). The agent will then attempt to start this service remotely to execute the payload. 

> This execution method requires you use a payload compatible with the `service_exe` payload wrapper.
