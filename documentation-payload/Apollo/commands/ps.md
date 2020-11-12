+++
title = "ps"
chapter = false
weight = 103
hidden = true
+++

## Summary
Retrieve list of running processes.

## Usage
```
ps
```

![ps](../images/ps.png)

## Detailed Summary
The `ps` command uses the `System.Diagnostics.Process.GetProcesses` method to collect information about running processes including process id, parent process id, process name, architecture, and user executing the process (High integrity required to collect other usernames).