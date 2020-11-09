+++
title = "execute_assembly"
chapter = false
weight = 103
hidden = false
+++

## Summary

Execute a .NET Framework assembly with the specified arguments. This assembly must first be cached in the agent using the `register_assembly` command.

### Arguments (positional)
#### assembly_name
The name of the assembly to execute. This must match the file name used with `register_assembly`.

#### arguments
Any arguments to be passed to the assembly during execution.

## Usage
```
execute_assembly [assembly_name] [arguments]
```

Example
```
execute_assembly SeatBelt.exe --groups=all
```

## Detailed Summary
The `execute_assembly` command uses a .NET Common Language Runtime loader to execute assemblies within a sacrificial process and return output over a named pipe back to the agent. This loader is injected into a process and then instantiates the CLR and passes the specified assembly as a byte array to be reflectively loaded into the process using `System.Reflection.Assembly.Load`. This assembly is then invoked and passed any inputted arguments while collecting the output to send back to the agent.

### Resources
- [DotNetReflectiveLoading](https://github.com/ambray/DotNetReflectiveLoading)
