+++
title = "unload_assembly"
chapter = false
weight = 103
hidden = false
+++

## Summary
Remove the specified assembly from the agent's cache of assemblies loaded via the `register_assembly` command.

### Arguments (positional)
#### assembly
The name of the assembly to remove from the agent's cache. This must be the same name as used when registering teh assembly.

## Usage
```
unload_assembly [assembly]
```

Example
```
unload_assembly SeatBelt.exe
```

## Detailed Usage
The `unload_assembly` command removes the specified assembly from the agent's cache. This command is only valid for assembly files that have been loaded with the `register_assembly` command. Apollo tracks these files using filename whent he assembly was loaded, which means this name must match when unloading so that it can correctly be found by the agent.
