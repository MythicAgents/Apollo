+++
title = "keylog"
chapter = false
weight = 103
hidden = false
+++

## Summary
Start a keylogger in a specified process.

### Arguments (positional)
#### pid
The target process's ID.

#### arch
The target process's architecture. Must be one of x86 or x64

## Usage
```
keylog [pid] [arch]
```
Example
```
keylog 1234 x64
```

## Detailed Summary
The `keylog` command uses the `GetAsyncKeyState` Windows API to log keystrokes and send them back to Mythic. This is done with a stand alone .NET assembly that is loaded with the CLR loader stub used for `execute_assembly`. The CLR loader is injected into the specified process and executes the keylogger assembly, which in turn will begin logging keystrokes and sending them over a named pipe to the agent.

Keystrokes can be found in the `Operational Views > Kelogs` page. These keystrokes are sorted by host, then user, then window title. When new keystrokes are retrieved, a balloon notification will appear in the top right notifying you of the new keystrokes.