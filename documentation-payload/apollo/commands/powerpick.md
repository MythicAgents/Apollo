+++
title = "powerpick"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Create, Process Inject, Process Kill
{{% /notice %}}

## Summary
Execute PowerShell commands as post-exploitation job. This command will import the most recently registered `*.ps1` file registered using `register_file` and import it into the PowerShell runspace before execution.

### Arguments (Positional)
#### command
PowerShell command to be executed.

## Usage
```
powerpick [command]
powerpick -Command [command]
```


## MITRE ATT&CK Mapping

- T1059
- T1562
