+++
title = "Fork and Run Commands"
chapter = false
weight = 102
+++

## What is Fork and Run?

"Fork and Run" is an agent architecture that spawns sacrificial processes in a suspended state to inject shellcode into.

## Fork and Run in Apollo

Apollo uses the fork and run architecture for a variety of jobs. These jobs will all first spawn a new process specified by the [`spawnto_x86`](/agents/apollo/commands/spawnto_x86) or [`spawnto_x64`](/agents/apollo/commands/spawnto_x64) commands. The parent process of these new processes is specified by the [`ppid`](/agents/apollo/commands/ppid/) command. Once the process is spawned, Apollo will use the currently set injection technique to inject into the remote process.

The following commands use the fork and run architecture:

- [`execute_assembly`](/agents/apollo/commands/execute_assembly/)
- [`mimikatz`](/agents/apollo/commands/mimikatz/)
- [`powerpick`](/agents/apollo/commands/powerpick/)
- [`printspoofer`](/agents/apollo/commands/printspoofer/)
- [`pth`](/agents/apollo/commands/pth/)
- [`dcsync`](/agents/apollo/commands/pth/)
- [`spawn`](/agents/apollo/commands/spawn/)
- [`execute_pe`](/agents/apollo/commands/execute_pe/)