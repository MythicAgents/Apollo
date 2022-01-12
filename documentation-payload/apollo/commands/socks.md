+++
title = "socks"
chapter = false
weight = 103
hidden = false
+++

## Summary
Start a SOCKS server to send traffic through your agent. When started, you can then bind to the specified port on the Mythic server, and use it to route traffic into the target network. Currently only TCP connections are supported. UDP operations will not return.

### Arguments

#### port
The port number to bind the Mythic SOCKSv5 server.

## Usage
```
socks [port]
```

Example
```
socks 7000
```

## MITRE ATT&CK Mapping

- T1090