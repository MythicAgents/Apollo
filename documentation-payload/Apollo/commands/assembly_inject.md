+++
title = "assembly_inject"
chapter = false
weight = 103
hidden = false
+++

## Summary

Inject the unmanaged .NET assembly loader into a remote process and execute an assembly registered with `register_assembly` within that process. 

### Arguments (modal popup)

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
assembly_inject
```
In the pop up menu
```
arch: [arch]
assembly_arguments: [assembly_arguments]
assembly_name: [assembly_name]
pid: [pid]
```

Example
```
assembly_inject
```
In the pop up menu
```
arch: x64
assembly_arguments: --group=all
assembly_name: SeatBelt.exe
pid: 1234
```

## Detailed Summary

The `assembly_inject` command uses process injection into a remote process to execute a .NET assembly in the context of the target process. This method uses the agent's current injection technique which can be viewed with `get_current_injection_technique`. For more information about the unmanaged .NET loader, see the page for `execute_assembly`.
