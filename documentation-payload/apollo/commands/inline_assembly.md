+++
title = "inline_assembly"
chapter = false
weight = 103
hidden = false
+++

## Summary

Execute a .NET Framework assembly in-process with the specified arguments. This assembly must first be cached in the agent using the `register_assembly` command before being executed.

{{% notice warning %}}
This command does not patch Environment.Exit, and as a result, should the assembly call this function, the agent itself will exit.
{{% /notice %}}

### Arguments

![exeasm](../images/inline_assembly.png)

#### Assembly
The name of the assembly to execute. This must match the file name used with `register_file`. 

#### Arguments (optional)
Arguments to pass to the assembly.

## Usage
```
inline_assembly -Assembly [assembly_name] -Arguments [arguments]
inline_assembly [assembly_name] [arguments]
```

Example
```
inline_assembly SeatBelt.exe --groups=all
```


## MITRE ATT&CK Mapping

- T1547


## Special Thanks
Mayllart submitted the initial PR for this module. You can find him on his socials here:

Social | Handle
-------|-------
Github|https://github.com/thiagomayllart
Twitter|[@thiagomayllart](https://twitter.com/thiagomayllart)
BloodHoundGang Slack|@Mayllart