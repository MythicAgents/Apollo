+++
title = "register_file"
chapter = false
weight = 103
hidden = false
+++

## Summary
Cache a file to be used in other post-exploitation jobs. If the file extension ends in `.ps1`, this file will be used in PowerShell post-exploitation jobs, such as `powershell`, `psinject`, and `powerpick`. Otherwise, these files are used by `assembly_inject`, `execute_assembly`, `inline_assembly`, or `execute_pe`.

By default, these files are cached in the agent using both AES256 and DPAPI encryption at rest, and decrypted only for task execution.

>Note: The type of executable (.NET assembly or unmanaged executable) is not tracked internally, so it's up to the operator to specify a correct executable for their command. e.g., do not provide Seatbelt.exe to `execute_pe`

### Arguments (Popup)
#### File
The file to cache in the agent for post-ex jobs.

## MITRE ATT&CK Mapping

- T1547