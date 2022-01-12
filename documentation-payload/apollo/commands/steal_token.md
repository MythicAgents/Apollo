+++
title = "steal_token"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
Artifacts
- Process Open
{{% /notice %}}

## Summary
Steal the primary token from another process. If no target process is specified, `winlogon.exe` will be the default target.

### Arguments (Positional)
#### pid
The process id to steal a primary access token from. This will default to `winlogon.exe` if no PID is provided. 

## Usage
```
steal_token [pid]
```
Example
```
steal_token 1234
```


## MITRE ATT&CK Mapping

- T1134
- T1528

## Detailed Summary
The `steal_token` command uses the `DuplicateTokenEx` Windows API to attempt to clone a process's primary access token and use this handle as the current thread's access token.
