+++
title = "mimikatz"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
Artifacts Generated: Process Create, Process Inject, Process Kill
{{% /notice %}}

## Summary
Execute one or more mimikatz commands.

### Arguments (Positional)
#### Command
The command you would like mimikatz to run. Some commands require certain privileges and may need the `token::elevate` Mimikatz command or the builtin equivalent [`getprivs`](/agents/apollo/commands/getprivs/) to be executed first.

## Usage
```
mimikatz -Command [command]
```

Example
```
mimikatz sekurlsa::logonpasswords
mimikatz -Command sekurlsa::logonpasswords
```


## MITRE ATT&CK Mapping

- T1134
- T1098
- T1547
- T1555
- T1003
- T1207
- T1558
- T1552
- T1550

## Detailed Summary
The `mimikatz` command uses a modified version of Mimikatz which is compiled as a DLL. This DLL is compiled into shellcode using [sRDI](https://github.com/monoxgas/sRDI) executed using Apollo's post-exploitation job architecture. This command uses standard mimikatz arguments (parent::subcommand) and does not auto elevate for commands unless specified. 

If you enter a command such as `sekurlsa::logonpasswords`, Apollo will attempt to parse the output and store the credentials in the Mythic server for later use.


{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}

### Resrouces
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
