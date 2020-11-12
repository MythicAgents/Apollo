+++
title = "kill"
chapter = false
weight = 103
hidden = true
+++

## Summary
Kill a process by process ID.

## Usage (Positional)
```
kill [pid]
```
Example
```
kill 1234
```

## Detailed Summary
The `kill` command uses the `System.Diagnostics.Process.Kill` method to kill the specified process. The access token for the agent's process will need the correct permissions to the target process in order to successfully kill it.
