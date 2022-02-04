+++
title = "get_injection_techniques"
chapter = false
weight = 103
hidden = false
+++

## Summary
Retrieve a list of available injection techniques the agent can use.

## Usage
```
get_injection_techniques
```

## Detailed Summary
The `get_injection_techniques` command displays the various process injection techniques the agent is capable of using for post-exploitation jobs. You can see the current technique being used by an agent with the [`get_injection_techniques`](/agents/apollo/commands/get_injection_techniques/) command. The technique can also be changed using the [`set_injection_technique`](/agents/apollo/commands/set_injection_technique/) command.

You are encouraged to create your own injection technique and submit a new pull request!

### Available techniques

#### CreateRemoteThread
"Classic" process injection technique that uses the `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread` Windows APIs to execute shellcode in a specified process.

#### Early-Bird QueueUserAPC
Works for all jobs spawning sacrificial processes, but mileage may vary for injection-type commands. Calls `VirtualAllocEx`, `WriteProcessMemory`, `QueueUserAPC` and `ResumeThread` calls.

#### NtCreateThreadEx
Leverages syscalls from the NTDLL library to directly invoke shellcode associated with `NtOpenProcess`, `NtClose`, `NtDuplicateObject`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx`


![get_injection_techniques](../images/get_injection_techniques.png)