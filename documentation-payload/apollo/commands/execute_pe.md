+++
title = "execute_pe"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
Artifacts
- Process Create
- Process Inject
- Process Kill
{{% /notice %}}

## Summary

Execute a statically compiled PE file (e.g., compiled with /MT) with the specified arguments. This PE must first be cached in the agent using the `register_assembly` command before being executed.

### Arguments
![exeasm](../images/execute_pe.png)
#### PE
The name of the assembly to execute. This must match the file name used with `register_assembly`. 

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

## Artifacts

- Process Create
- Process Inject
- Process Kill

## Detailed Summary


### Resources
- [RunPE](https://github.com/nettitude/RunPE)
