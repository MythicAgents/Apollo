+++
title = "psimport"
chapter = false
weight = 103
hidden = true
+++

## Summary
Load PowerShell scripts into the agent's cache for user with the [`powershell`](/agents/apollo/commands/powershell/), [`psinject`](/agents/apollo/commands/psinject/), and [`powerpick`](/agents/apollo/commands/powerpick/) commands.

### Arguments (Popup)
#### PowerShell Script
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


## MITRE ATT&CK Mapping

- T1059

## Detailed Summary
The `psimport` command allows storing cached versions of PowerShell scripts as byte arrays within the agent process's memory. These byte arrays are loaded into the PowerShell runspace for any use of the [`powershell`](/agents/apollo/commands/powershell/), [`psinject`](/agents/apollo/commands/psinject/), and [`powerpick`](/agents/apollo/commands/powerpick/) commands, which allows these commands to execute functions and methods of these scripts. The agent can cache and load multiple PowerShell scripts.
> PowerShell scripts can be removed from the agent's cache using the [`psclear`](/agents/apollo/commands/psclear) command.
