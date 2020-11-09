+++
title = "ps_full"
chapter = false
weight = 103
hidden = false
+++

## Summary
Retrieve detailed list of running processes.

## Usage
```
ps_full
```

## Detailed Summary
The `ps_full` command uses the `System.Diagnostics.Process.GetProcesses` method to collect information about running processes including process id, parent process id, process name, user running the process, architecture, integrity level, description, developer name, session id, command line arguments, file path, and the process window tile.

![ps_full](../images/ps_full.png)

When clicking the informational icon next to the process name, the following additional information can be seen. If the information icon is red, the process is running with HIGH or SYSTEM integrity level. 

![ps_full_additional_info](../images/ps_full2.png)