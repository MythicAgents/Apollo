+++
title = "assembly_inject"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Inject
{{% /notice %}}

## Summary

Inject the .NET assembly loader into a remote process and execute an assembly registered with `register_file`. This assembly is injected into the remote process using the injection technique currently specified by `get_injection_techniques`.

### Arguments (Positional or Popup)

![args](../images/assembly_inject.png)

#### Arguments
Any arguments to be executed with the assembly.

#### Assembly
Name used when registering assembly with the `register_file` command (e.g., `Seatbelt.exe`)

#### PID
Process ID to inject into.

## Usage
```
assembly_inject -PID 7344 -Assembly Seatbelt.exe -Arguments DotNet
```

Example

![ex](../images/assembly_inject_resp.png)

## MITRE ATT&CK Mapping

- T1055