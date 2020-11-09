+++
title = "SMB (Currently Defunct)"
chapter = false
weight = 102
+++

{{% notice warning %}}
The SMB profile is currently defunct and non-operational.
{{% /notice %}}

## Summary
Apollo implents peer-to-peer communications through the use of named pipes. This enables C2 traffic to traverse over SMB within an internal network before egressing traffic through an HTTP Apollo agent to the Mythic server.

### C2 Workflow
{{<mermaid>}}
sequenceDiagram
    participant Mythic
    participant Egress Agent
    participant P2P Agent
    Egress Agent->>Mythic: POST to receive taskings from server
    Mythic-->>Egress Agent: send taskings in server response
    Egress Agent->>P2P Agent: send taskings over Named Pipe
    P2P Agent->>Egress Agent: send task response over Named Pipe 
    Egress Agent->>Mythic: POST task response to server
    Mythic-->>Egress Agent: send task status in server response
    Egress Agent->>P2P Agent: send server response over Named Pipe
{{< /mermaid >}}

### HTTP Egress
The SMB C2 profile is designed to be used for internal network communication, and therefore will need to egress from a network through an agent using the HTTP C2 profile. All HTTP agents have the ability to communicate with SMB agents and manage peer-to-peer connections using the `link` and `unlink` commands.

### Profile Options
#### Base64 of 32-byte AES Key
The AES PSK used to encrypt agent communication.

#### Pipe Name
The name of the created name pipe to use for agent communication.

### Agent Options
#### Target architecture
The processor architecture to target, can be `x86`, `x64`, or `AnyCPU`.

#### Build Target
Choose whether to build the agent in a debugging build.

#### Output Type
Choose the payload output type, this can be as `WinEXE`, `DLL`, or `Raw`. If `Raw` is chosen, Mythic will compile the agent as `WinEXE` and pass it through `donut` to create shellcode.

#### .NET Framework Version
Choose the version of the .NET framework to compile to. Only 4.0 is supported.
