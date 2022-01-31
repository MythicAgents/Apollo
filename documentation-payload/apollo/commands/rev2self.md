+++
title = "rev2self"
chapter = false
weight = 103
hidden = false
+++

## Summary
Revert to agent's primary token.

## Usage
```
rev2self
```

## Detailed Summary
The `rev2self` command uses the `SetThreadToken` Windows API to revert the current thread's access token to the process's primary token.
