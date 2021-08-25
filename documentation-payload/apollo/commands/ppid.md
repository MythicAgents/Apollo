+++
title = "ppid"
chapter = false
weight = 103
hidden = true
+++

## Summary
Set the parent process to the specified process identifier for all post-exploitation jobs.

## Usage
```
ppid [pid]
```

## Detailed Summary
The `ppid` command will set the parent process to the specified process identifier for all post-exploitation jobs. This is one of two attributes you can set for fork-and-run jobs, which all start up using the StartupInfoEx structure.