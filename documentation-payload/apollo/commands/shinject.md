+++
title = "shinject"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
Artifacts
- Process Inject
{{% /notice %}}

## Summary
Inject arbitrary shellcode into a remote process.

### Arguments (Popup)
#### PID
Target process ID to inject into.

#### Shellcode
File containing position independant shellcode.

## Usage
```
shinject
```
In pop up menu
```
pid: [pid]
shellcode: [file selector]
```

Example
```
shinject
```
In pop up menu
```
pid: 1234
File: apollo.bin
```

## MITRE ATT&CK Mapping

- T1055

## Detailed Summary
The `shinject` command will use the agent's current injection technique to inject the given shellcode into a remote process.
