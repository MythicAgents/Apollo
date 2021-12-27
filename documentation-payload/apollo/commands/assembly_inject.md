+++
title = "assembly_inject"
chapter = false
weight = 103
hidden = true
+++

## Summary

Inject the .NET assembly loader into a remote process and execute an assembly registered with `register_file`. 

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

## Detailed Summary

The `assembly_inject` command uses the currently set process injection technique to inject into a remote process and execute a .NET assembly in the context of the target process. To see what injection technique is in use, you can use the `get_injection_technique` command.