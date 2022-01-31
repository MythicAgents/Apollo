+++
title = "run"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Create
{{% /notice %}}

## Summary
Execute a binary with any specified arguments. Command will use %PATH% without needing to use full paths.

### Arguments
#### Executable
Executable binary to run.

#### Arguments
Any arguments to the binary being executed.

## Usage
```
run -Executable [binary] -Arguments [arguments]
```

Example
```
run -Executable ipconfig -Arguments /all
```

## MITRE ATT&CK Mapping

- T1106
- T1218
- T1553