+++
title = "set_injection_technique"
chapter = false
weight = 103
hidden = false
+++

## Summary
Change the process injection technique the agent will use for post-exploitation jobs.

## Usage (positional)
```
set_injection_technique [technique]
```
Example
```
set_injection_technique CreateRemoteThreadInjection
```

## Detailed Summary
The `set_injection_technique` command sets the process injection technique the agent will use for post-exploitation jobs. You can see the current technique being used by an agent with the `get_current_injection_technique` command.  Available techniques can be viewed using the `list_injection_techniques` command.
