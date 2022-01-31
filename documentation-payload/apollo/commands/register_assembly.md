+++
title = "register_assembly"
chapter = false
weight = 103
hidden = false
+++

## Summary
Cache a .NET assembly to be used in other post-exploitation jobs. This command is a thin wrapper around the [`register_file`](/agents/apollo/commands/register_file/) command.

By default, these files are cached in the agent using both AES256 at rest, and decrypted only for task execution.

### Arguments (Popup)
#### File
The file to cache in the agent for post-ex jobs.

## MITRE ATT&CK Mapping

- T1547