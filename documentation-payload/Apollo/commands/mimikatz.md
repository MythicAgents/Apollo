+++
title = "mimikatz"
chapter = false
weight = 103
hidden = false
+++

## Summary
Execute one or more mimikatz commands.

### Arguments (positional)
#### command
The command you would like mimikatz to run. Some commands require certain privileges and may need the `token::elevate` Mimikatz command or the builtin equivalent `getprivs` to be executed first.

## Usage
```
mimikatz [command]
```

Example
```
mimikatz sekurlsa::logonpasswords
```

## Detailed Usage
The `mimikatz` command uses a modified version of Mimikatz which is compiled as a DLL. This DLL is compiled into shellcode using [sRDI](https://github.com/monoxgas/sRDI) executed using Apollo's post-exploitation job architecture. This command uses standard mimikatz arguments (parent::subcommand) and does not auto elevate for commands unless specified. 

### Resrouces
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
