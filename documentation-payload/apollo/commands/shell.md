+++
title = "shell"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Create
{{% /notice %}}

## Summary
Execute a shell command using `cmd.exe /c`.

### Arguments (Positional)
#### Command
Command to be executed.

#### Arguments
Any arguments to the command to be executed.

## Usage
```
shell [command] [arguments]
```

Example
```
shell ipconfig /all
```

## MITRE ATT&CK Mapping

- T1059