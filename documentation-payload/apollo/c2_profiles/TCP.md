+++
title = "TCP"
chapter = false
weight = 102
+++

## Summary
Peer-to-peer communication over a network socket. Apollo will bind to a specified port and await an incoming link request before establishing communications back to Mythic.

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
The TCP C2 profile is designed to be used for internal network communication, and therefore will need to egress from a network through an agent using the HTTP C2 profile. All HTTP agents have the ability to communicate with TCP agents and manage peer-to-peer connections using the `link` and `unlink` commands.

### Profile Options
#### Crypto type
Leave as aes256_hmac.

#### Port to start Apollo on
Self explanatory. Note: If medium integrity or lower, this will prompt a request to allow the binary to bind on the specified port.

#### Kill Date
The date at which the agent will stop calling back.

#### Perform Key Exchange
Perform encrypted key exchange with Mythic. Recommended to leave as T for true.