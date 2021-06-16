+++
title = "inject"
chapter = false
weight = 103
hidden = true
+++

## Summary
Inject agent shellcode into a specified process.

### Arguments (Popup)

![args](../images/inject01.png)

#### Architecture
The target process's architecture. Must be x86 or x64

#### PID
The target process's ID to inject the agent into.

#### Payload Template
The template to generate new shellcode from. Note: The template _must_ be shellcode for inject to succeed. This is the "Raw" output type when building Apollo.

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
template: Apollo.bin - Shellcode
```


## MITRE ATT&CK Mapping

- T1055

## Detailed Summary
The `inject` command uses TheWover's `donut` to turn an Apollo payload into shellcode. This shellcode is then injected using the agent's current process injection technique into the specified remote process.

### Resources
- [donut](https://github.com/TheWover/donut)
