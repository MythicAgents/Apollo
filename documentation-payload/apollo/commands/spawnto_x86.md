+++
title = "spawnto_x86"
chapter = false
weight = 103
hidden = true
+++

## Summary
Specify the default binary to be used for 32-bit post-exploitation jobs.

### Arguments (Positional or Popup)
#### path
Specify the full path to a binary to spawn for 32-bit post-exploitation jobs.

#### args or arguments
Optional arguments to pass to the spawned binary.

## Usage
```
spawnto_x86 [path] [args]
```

## MITRE ATT&CK Mapping

- T1055

## Detailed Summary
The `spawnto_x86` command allows specifying what binary to spawn for taskings that use Apollo's fork and run post exploitation architecture.

