+++
title = "shinject"
chapter = false
weight = 103
hidden = false
+++

## Summary
Inject arbitrary shellcode into a remote process.

### Arguments (modal popup)
#### pid
Target process ID to inject into.

#### shellcode
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

## Detailed Usage
The `shinject` command will use the agent's current injection technique to inject the given shellcode into a remote process.
