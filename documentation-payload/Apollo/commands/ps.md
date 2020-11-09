+++
title = "ps"
chapter = false
weight = 103
hidden = false
+++

## Summary
Retrieve list of running processes.

## Usage
```
ps
```

## Detailed Summary
The `ps` command uses the `System.Diagnostics.Process.GetProcesses` method to collect information about running processes including process id, parent process id, process name, architecture, and user executing the process (High integrity required to collect other usernames).

![ps](../images/ps.png)