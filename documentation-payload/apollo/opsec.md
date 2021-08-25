+++
title = "OPSEC"
chapter = false
weight = 10
pre = "<b>1. </b>"
+++

## Considerations

Below are considerations about Apollo's underlying behavior that may affect decisions during operation. Use this as a guide to ensure proper OPSEC and avoid detection when using Apollo.

## Injection Commands

Some commands use process injection to inject command modules into remote processes. The agent's process injection techniques can be managed with the follwing commands:

- [`get_current_injection_technique`](/agents/apollo/commands/get_current_injection_technique/)
- [`list_injection_techniques`](/agents/apollo/commands/list_injection_techniques/)
- [`set_injection_technique`](/agents/apollo/commands/set_injection_technique/)

### Fork and Run Commands

Some of Apollo's commands use a fork and run job architecture that will spawn a sacrificial process and inject the command module using the current injection technique. The following commands use this method for post-exploitation jobs:

- [`execute_assembly`](/agents/apollo/commands/execute_assembly/)
- [`mimikatz`](/agents/apollo/commands/mimikatz/)
- [`powerpick`](/agents/apollo/commands/powerpick/)
- [`printspoofer`](/agents/apollo/commands/printspoofer/)
- [`pth`](/agents/apollo/commands/pth/)
- [`spawn`](/agents/apollo/commands/spawn/)

The following commands use remote process injection:

- [`assembly_inject`](/agents/apollo/commands/assembly_inject/)
- [`inject`](/agents/apollo/commands/inject/)
- [`keylog`](/agents/apollo/commands/keylog/)
- [`psinject`](/agents/apollo/commands/psinject/)
- [`shinject`](/agents/apollo/commands/shinject/)

> Note: If your injection technique is set to QueueUserAPC, these commands will fail as only the "early bird" method of QueueUserAPC is implemented.

## Process Execution Commands

### shell

The [`shell`](/agents/apollo/commands/shell/) command will execute a given command through `cmd.exe` using the `/c` argument. Some telemtry and detections may be built around this behavior. If shell capabilities are not needed, it is recommended to use the [`run`](/agents/apollo/commands/run/) command.

### run

The [`run`](/agents/apollo/commands/run/) command allows executing on disk binaries without the use of `cmd.exe`. This can be used when trying to avoid telemetry around `cmd.exe`

## Service Creation

The following commands interact with the Service Control Manager of the current or a remote host to create a service. If later parts of a command fail, it will delete the original service that was created.

- [`psexec`](/agents/apollo/commands/psexec/)

## Evasion

Apollo implements a handful of evasion commands to help an operator execute post-exploitation jobs on target. You can change parent-child process relationships by spoofing parent process id via [`ppid`](/agents/apollo/commands/spawnto_x86), block non-Microsoft signed DLLs from loading into your sacrificial processes via [`blockdlls`](/agents/apollo/commands/blockdlls/), and changing what applications you can spawn and inject into via [`spawnto_x64`](/agents/apollo/commands/spawnto_x64/) and [`spawnto_x86`](/agents/apollo/commands/spawnto_x86/)

### Spawnto

For commands listed under `Post-Exploitation Jobs`, there will be a sacrificial process spawned as part of Apollo's fork and run architecture. This process is set to `C:\Windows\System32\rundll32.exe` by default, but can be changed with the following commands:

- [`spawnto_x64`](/agents/apollo/commands/spawnto_x64/)
- [`spawnto_x86`](/agents/apollo/commands/spawnto_x86/)
