+++
title = "keylog"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Inject
{{% /notice %}}

## Summary
Start a keylogger in a specified process.

### Arguments (Positional)
#### PID
The target process's ID to inject the keylogging stub.

## Usage
```
keylog_inject -PID [pid]
```
Example
```
keylog -PID 1234
```


## MITRE ATT&CK Mapping

- T1056

## Artifacts

- Process Inject

## Detailed Summary
The `keylog` command uses the `GetAsyncKeyState` Windows API to log keystrokes and send them back to Mythic. This is done with a stand alone .NET assembly that is loaded with the CLR loader stub used for `execute_assembly`. The CLR loader is injected into the specified process and executes the keylogger assembly, which in turn will begin logging keystrokes and sending them over a named pipe to the agent.

Keystrokes can be found in the `Operational Views > Kelogs` page. These keystrokes are sorted by host, then user, then window title. When new keystrokes are retrieved, a balloon notification will appear in the top right notifying you of the new keystrokes.

![keylogs](../images/keylog01.png)