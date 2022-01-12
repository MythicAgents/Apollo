+++
title = "execute_pe"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Create, Process Inject, Process Kill
{{% /notice %}}

## Summary

Execute a statically compiled PE file (e.g., compiled with /MT) with the specified arguments. This PE must first be cached in the agent using the `register_file` command before being executed.

{{% notice info %}}
Executables must be compiled for the architecture of the machine. e.g., if Apollo is running on a 64-bit machine, compile the executable for x64.
{{% /notice %}}

This is based on the work put forward by Nettitude's [RunPE](https://github.com/nettitude/RunPE) project with modifications.

### Arguments
![exepe](../images/execute_pe.png)

#### PE
The name of the assembly to execute. This must match the file name used with `register_file`. 

#### Arguments (optional)
Arguments to pass to the assembly.

## Usage
```
execute_pe -PE [pe_name] -Arguments [arguments]
execute_pe [pe_name] [arguments]
```

Example
```
execute_pe -PE SpoolSample.exe -Arguments "127.0.0.1 127.0.0.1"
execute_pe SpoolSample.exe 127.0.0.1 127.0.0.1
```


## MITRE ATT&CK Mapping

- T1547

### Resources
- [RunPE](https://github.com/nettitude/RunPE)
