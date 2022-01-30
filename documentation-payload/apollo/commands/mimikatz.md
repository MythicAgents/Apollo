+++
title = "mimikatz"
chapter = false
weight = 103
hidden = false
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

### Resrouces
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
