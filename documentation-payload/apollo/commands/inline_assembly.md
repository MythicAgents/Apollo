+++
title = "inline_assembly"
chapter = false
weight = 103
hidden = false
+++

## Summary

Execute a .NET Framework assembly in-process with the specified arguments. This assembly must first be cached in the agent using the `register_assembly` command before being executed.

### Arguments

![exeasm](../images/inline_assembly.png)

#### Assembly
The name of the assembly to execute. This must match the file name used with `register_file`. 

#### Arguments (optional)
Arguments to pass to the assembly.

## Usage
```
inline_assembly -Assembly [assembly_name] -Arguments [arguments]
inline_assembly [assembly_name] [arguments]
```

Example
```
inline_assembly SeatBelt.exe --groups=all
```


## MITRE ATT&CK Mapping

- T1547
