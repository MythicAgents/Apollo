+++
title = "powershell"
chapter = false
weight = 103
hidden = false
+++

## Summary
Run PowerShell commands in the current running process.

### Arguments (Positional)
#### Command
PowerShell command to be executed.

## Usage
```
powershell [command]
powershell -Command [command]
```

Example
```
powershell Get-Process
```

## MITRE ATT&CK Mapping

- T1059

## Detailed Summary
The `powershell` creates a new PowerShell runspace **within the Apollo process** to execute given PowerShell commands. Any PowerShell scripts loaded with the [`psimport`](/agents/apollo/commands/psimport/) command will be loaded into the runspace before command execution, giving access to any cmdlets within those scripts. This method also bypasses the system's PowerShell execution settings before executing commands. PowerShellv4 is used by default.
