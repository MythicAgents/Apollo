+++
title = "register_assembly"
chapter = false
weight = 103
hidden = true
+++

## Summary
Loads a .NET assembly into an agent's cache for later use with [`execute_assembly`](/agents/apollo/commands/execute_assembly/) and [`assembly_inject`](/agents/apollo/commands/assembly_inject/) commands.

### Arguments (Popup)
#### assembly
The .NET assembly to be uploaded to the agent for later use.

## Usage
```
register_assembly
```
In the pop up menu
```
assembly: [file]
```
Example
```
register_assembly
```
In the pop up menu
```
assembly: SeatBelt.exe
```


## MITRE ATT&CK Mapping

- T1547

## Detailed Summary
The `register_assembly` command allows storing cached versions of .NET assemblies as byte arrays within the agent process's memory. These byte arrays are loaded into the CLR loader when the assembly is called via the [`execute_assembly`](/agents/apollo/commands/execute_assembly/) and [`assembly_inject`](/agents/apollo/commands/assembly_inject/) commands.
> Assemblies can be removed from the agent's cache using the [`unload_assembly`](/agents/apollo/commands/unload_assembly/) command. To overwrite a cached assembly, simply issue `register_assembly` again.