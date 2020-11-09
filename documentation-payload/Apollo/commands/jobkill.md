+++
title = "jobkill"
chapter = false
weight = 103
hidden = false
+++

## Summary
Kill a running job for an agent.

## Usage
```
jobkill [job id]
```
Example
```
jobkill 1
```

## Detailed Summary
The `jobkill` command kills a job's executing thread using the `Thread.Abort` method to kill the thread.
