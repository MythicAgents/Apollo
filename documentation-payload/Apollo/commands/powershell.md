+++
title = "powershell"
chapter = false
weight = 103
hidden = false
+++

## Summary
Run PowerShell commands in the current running process.

### Arguments (positional)
#### command
PowerShell command to be executed.

## Usage
```
powershell [command]
```

Example
```
powershell Get-Process
```

## Detailed Summary
The `powershell` creates a new PowerShell runspace within the agent's current process to execute given PowerShell commands. Any PowerShell scripts loaded with the `psimport` command will be loaded into the runspace before command execution, giving access to any cmdlets within those scripts. This method also bypasses the system's PowerShell execution settings before executing commands. PowerShellv4 is used by default.
