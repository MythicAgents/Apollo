+++
title = "execute_assembly"
chapter = false
weight = 103
hidden = true
+++

## Summary

Execute a .NET Framework assembly with the specified arguments. This assembly must first be cached in the agent using the `register_assembly` command before being executed.

### Arguments (Positional)
#### assembly_name
The name of the assembly to execute. This must match the file name used with `register_assembly`. If you have questions as to what assemblies are available, you can issue [`list_assemblies`](/agents/apollo/commands/list_assemblies/). 

#### arguments (optional)
Arguments to pass to the assembly.

## Usage
```
execute_assembly [assembly_name] [arguments]
```

Example
```
execute_assembly SeatBelt.exe --groups=all
```


## MITRE ATT&CK Mapping

- T1547

## Detailed Summary
The `execute_assembly` command uses a .NET Common Language Runtime loader to execute assemblies within a sacrificial process and return output over a named pipe back to the agent. This loader is injected into a sacrificial process (specified by the `spawnto_*` commands) and passes the assembly's bytes over a named pipe, which is then loaded reflectively using `System.Reflection.Assembly.Load`. This assembly is then invoked and passed any passed arguments while streaming data over the named pipe.

This creates a new artifact relating to the sacrificial process spawned, which can be viewed in the artifacts page.

### Resources
- [DotNetReflectiveLoading](https://github.com/ambray/DotNetReflectiveLoading)
