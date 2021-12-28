+++
title = "blockdlls"
chapter = false
weight = 103
hidden = true
+++

## Summary
Prevent non-Microsoft signed DLLs from loading into post-exploitation jobs.

## Usage
```
blockdlls
blockdlls -EnableBlock [true|false]
```

## Detailed Summary
The `blockdlls` command will set the process mitigation policy to Microsoft-signed only. This is one of two process attributes you can set in fork and run jobs, and is set via the StartupInfoEx structure.