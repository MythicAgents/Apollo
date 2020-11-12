+++
title = "shell"
chapter = false
weight = 103
hidden = true
+++

## Summary
Execute a shell command using `cmd.exe /c`.

### Arguments (Positional)
#### Command
Command to be executed.

#### Arguments
Any arguments to the command to be executed.

## Usage
```
shell [command] [arguments]
```

Example
```
shell ipconfig /all
```

## Detailed Summary
The `shell` command spawns a `cmd.exe` process and executes the given command via the `/c` argument. Any standard output or standard errors are returned to Apollo over an anonymous named pipe to be returned to Mythic.

{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}