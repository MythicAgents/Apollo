+++
title = "getprivs"
chapter = false
weight = 103
hidden = true
+++

## Summary
Enable as many privileges as possible for your current access token.

## Usage
```
getprivs
```

## Detailed Summary
The `getprivs` command uses the `AdjustTokenPrivileges` Windows API to enable all privileges assigned to the current thread's token.