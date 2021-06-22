+++
title = "ps_full"
chapter = false
weight = 103
hidden = true
+++

## Summary
Retrieve detailed list of running processes.

## Usage
```
ps_full
```

![ps_full](../images/ps_full.png)

When clicking the informational icon next to the process name, the following additional information can be seen. If the information icon is red, the process is running with HIGH or SYSTEM integrity level. 

![ps_full_additional_info](../images/ps_full02.png)

This process listing also integrates with Mythic's process explorer as seen below.

![process explorer](../images/ps_full03.png)

## MITRE ATT&CK Mapping

- T1106

## Detailed Summary
The `ps_full` command uses the `System.Diagnostics.Process.GetProcesses` method to collect information about running processes including process id, parent process id, process name, user running the process, architecture, integrity level, description, developer name, session id, command line arguments, file path, and the process window tile.