+++
title = "spawn"
chapter = false
weight = 103
hidden = true
+++

## Summary
Spawn a new Apollo agent based off the payload template given. (Note: Must be `Raw` format.)

### Arguments (Popup)
#### Payload Template
Template used to build and spawn a new agent from. This template must be of format `Raw` (aka shellcode) in order for this command to generate a new callback.

## Usage
```
spawn
```


## MITRE ATT&CK Mapping

- T1055

{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}