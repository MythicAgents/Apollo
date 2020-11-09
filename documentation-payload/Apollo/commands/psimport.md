+++
title = "psimport"
chapter = false
weight = 103
hidden = false
+++

## Summary
Load PowerShell scripts into the agent's cache for user with the `powershell`, `powerpick`, and `psinject` commands.

### Arguments (modal popup)
#### file
The PowerShell script to be uploaded to the agent for later use.

## Usage
```
psimport
```
In the pop up menu
```
file: [file]
```
Example
```
psimport
```
In the pop up menu
```
file: PowerView.ps1
```

## Detailed Summary
The `psimport` command allows storing cached versions of PowerShell scripts as byte arrays within the agent process's memory. These byte arrays are loaded into the PowerShell runspace for any use of the `powershell`, `powerpick` or `psinject` commands, which allows these commands to execute functions and methods of these scripts. The agent can cache and load multiple PowerShell scripts.
> PowerShell scripts can be removed from the agent's cache using the `psclear` command.
