+++
title = "assembly_inject"
chapter = false
weight = 103
hidden = true
+++

## Summary

Inject the unmanaged .NET assembly loader into a remote process and execute an assembly registered with `register_assembly` within that process. 

### Arguments (Positional or Popup)

![args](../images/assembly_inject01.png)

#### arch
Target process architecture. Must be x86 or x64

#### assembly_arguments
Any arguments to be executed with the assembly.

#### assembly_name
Name used when registering assembly with the `register_assembly` command.

#### pid
Process ID to inject into.

## Usage
```
assembly_inject [pid] [x86|x64] [assembly] [args]
```

Example

![ex](../images/assembly_inject02.png)

## MITRE ATT&CK Mapping

- T1055

## Detailed Summary

The `assembly_inject` command uses the currently set process injection technique to inject into a remote process and execute a .NET assembly in the context of the target process. To see what injection technique is in use, you can use the `get_injection_technique` command.