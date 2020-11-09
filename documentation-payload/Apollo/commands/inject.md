+++
title = "inject"
chapter = false
weight = 103
hidden = false
+++

## Summary
Inject agent shellcode into a specified process.

### Arguments (modal popup)
#### arch
The target process's architecture. Must be x86 or x64

#### pid
The target process's ID.

#### template
Select the payload template to generate shellcode for.

## Usage
```
inject
```
In the pop up menu
```
arch: [arch]
pid: [pid]
template: [drop down menu of created payloads]
```

Exmaple
```
inject
```
In the pop up menu
```
arch: x64
pid: 1234
template: Apollo - HTTP,SMBServer
```

## Detailed Usage
The `inject` command uses `donut` to turn an agent payload into shellcode. This shellcode is then injected using the agent's current process injection technique into the specified remote process.

### Resources
- [donut](https://github.com/TheWover/donut)
