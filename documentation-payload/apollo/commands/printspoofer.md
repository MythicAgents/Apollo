+++
title = "printspoofer"
chapter = false
weight = 103
hidden = true
+++

## Summary
Inject a [printspoofer](https://github.com/itm4n/PrintSpoofer) DLL to execute a given command as SYSTEM. This will only succeed if the user has `SE_IMPERSONATE` privileges.

This DLL is injected with respect to the current injection technique, and spawns a sacrificial process designated by the `spawnto_*` commands.

## Usage
Execute `apollo.exe` as `SYSTEM`
```
printspoofer -c apollo.exe
```

{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}


## MITRE ATT&CK Mapping

- T1547

## References

- https://github.com/itm4n/PrintSpoofer