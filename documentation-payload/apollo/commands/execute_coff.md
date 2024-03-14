+++
title = "execute_coff"
chapter = false
weight = 103
hidden = false
+++

## Summary

Execute a Beacon Object File (BOF) with the specified arguments. This object file must first be cached in the agent using the `register_coff` command before being executed.
The `RunOF.dll` ia now automatically obtained from mythic if Apollo does not have it loaded in its file store already. 

### Arguments

![execoff](../images/execute_coff.png)

#### Object File
The name of the object file to execute. This must match the file name used with `register_file` or `register_coff`.

#### Function
Function of the object file to call, usually 'go'.

#### TimeOut
Maximum time (in seconds) that the object file should run.

#### Arguments (optional)
Arguments to pass to the function, using the following format:

-s:123 or int16:123
-i:123 or int32:123
-z:hello or string:hello
-Z:hello or wchar:hello
-b:abc== or base64:abc==

## Usage
```
execute_coff -Coff [coff_name] -Function [go] -Timeout [30] [-Arguments [arguments]]
```

Example
```
execute_coff -Coff dir.x64.o -Function go -Timeout 30 -Arguments wchar:C:\\
```

## MITRE ATT&CK Mapping

- T1027

## Detailed Summary
The `execute_coff` command uses a Object File loader to execute object files within a new thread and returning output back to the agent using the implementation of Beacon functions.

### Resources
- [RunOF](https://github.com/nettitude/RunOF)
