+++
title = "run"
chapter = false
weight = 103
hidden = true
+++

## Summary
Execute a binary with any specified arguments. Command will use %PATH% without needing to use full paths.

### Arguments (positional)
#### binary
Executable binary to run.

#### arguments
Any arguments to the binary being executed.

## Usage
```
run [binary] [arguments]
```

Example
```
run ipconfig /all
```

## MITRE ATT&CK Mapping

- T1106
- T1218
- T1553

## Detailed Summary
The `run` command executes the specified binary with any supplied arguments. Any standard output or standard errors are returned to Apollo over an anonymous named pipe to be returned to Mythic.

{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}