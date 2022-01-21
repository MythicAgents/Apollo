+++
title = "inject"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Inject
{{% /notice %}}

## Summary
Inject agent shellcode into a specified process.

### Arguments (Popup)

![args](../images/inject.png)

#### PID
The target process's ID to inject the agent into.

#### Payload Template
The template to generate new shellcode from. Note: The template _must_ be shellcode for inject to succeed. This is the "Raw" output type when building Apollo.

## Usage
```
inject
```

## MITRE ATT&CK Mapping

- T1055