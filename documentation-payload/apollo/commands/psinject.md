+++
title = "psinject"
chapter = false
weight = 103
hidden = true
+++
 
## Summary
Execute PowerShell commands in a remote process.

### Arguments (Positional or Popup)
#### PID
Target process ID.

#### Architecture
Target process architecture. Must be x86 or x64.

#### Command
PowerShell command to be executed.

## Usage
```
psinject [pid] [arch] [command]
```

Example
```
psinject 1234 x64 Get-Process
```


## MITRE ATT&CK Mapping

- T1059
- T1055

## Detailed Summary
The `psinject` command uses process injection into a remote process to execute PowerShell commands in the context of the target process. This method uses the agent’s current injection technique which can be viewed with [`get_current_injection_technique`](/agents/apollo/commands/get_current_injection_technique/).
