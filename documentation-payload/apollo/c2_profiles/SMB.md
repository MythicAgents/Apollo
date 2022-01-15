+++
title = "SMB"
chapter = false
weight = 102
+++

## Summary
Peer-to-peer communication over a named pipe. This enables C2 traffic to traverse over SMB within an internal network before egressing traffic through an HTTP Apollo agent to the Mythic server.

Install via:
```
mythic-cli install github https://github.com/MythicC2Profiles/smb.git
```

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

### Profile Options
The SMB C2 profile is designed to be used for internal network communication, and therefore will need to egress from a network through an agent using the HTTP C2 profile. All HTTP agents have the ability to communicate with SMB agents and manage peer-to-peer connections using the `link` and `unlink` commands.

### Profile Options
#### Crypto type
Leave as aes256_hmac.

#### Named Pipe
The name of the created name pipe to use for agent communication. Recommended to use the randomly generated UUID provided.

#### Kill Date
The date at which the agent will stop calling back.

#### Perform Key Exchange
Perform encrypted key exchange with Mythic. Recommended to leave as T for true.