+++
title = "OPSEC"
chapter = false
weight = 10
pre = "<b>2. </b>"
+++

## Considerations

Below are considerations about Apollo's underlying behavior that may affect decisions during operation. Use this as a guide to ensure proper OPSEC and avoid detection when using Apollo.

### Post-Exploitation Jobs

Some of Apollo's commands use a fork and run job architecture that will spawn a process, and inject the capability into it using process injection. This is done for stability of the agent. The following commands use this method for post-exploitation jobs:

- `execute_assembly`
- `mimikatz`
- `powerpick`
- `printspoofer`
- `pth`

### Remote Process Injection

Some commands use process injection to inject capabilities into remote processes. The agent's process injection techniques can be managed with the `get_current_injection_technique`, `list_injection_techniques` and `set_injection_technique` commands. The following commands use remote process injection:

- `assembly_inject`
- `inject`
- `keylog`
- `psinject`
- `shinject`

### Process Execution

#### shell

The `shell` command will execute a given command through `cmd.exe` using the `/c` argument. Some telemtry and detections may be built around this behavior. If shell capabilities are not needed, it is recommended to use the `run` command.

#### run

The `run` command allows executing on disk binaries without the use of `cmd.exe`. This can be used when trying to avoid telemetry around `cmd.exe`

### Service Creation

The following commands interact with the Service Control Manager of the current or a remote host to create a service. If later parts of a command fail, it will delete the original service that was created.

- `psexec`

## Evasion

### Spawnto

For commands listed under `Post-Exploitation Jobs`, there will be a sacrificial process spawned as part of Apollo's fork and run architecture. This process is set to `C:\Windows\System32\cmd.exe` by default, but can be changed with the following commands:

- `spawnto_x64`
- `spawnto_x86`
