+++
title = "rportfwd"
chapter = false
weight = 103
hidden = true
+++

## Summary
Forward traffic from an attacker controlled machine to a service specified by the remote address and port.

### Arguments (Positional or Popup)

#### action (required)
Must be one of:
- start - Begin the port forwarding.
- stop - Stop the port forwarding.
- list - List running port forwards.
- flush - Flush the connection cache.

#### port (optional)
The port number you'll connect to on the Mythic server to send and receive traffic. Mandatory for `start` and `stop` actions.

#### rport (optional)
The remote port the traffic is destined for. Mandatory for `start` action.

#### rip (optional)
The remote IP the traffic is destined for. Mandatory for the `start` action.


## Usage
```
rportfwd [action] [port] [rport] [rip]
```

Example
```
rportfwd start 1234 8.8.8.8 53
```

## MITRE ATT&CK Mapping

- T1090

## Detailed Summary
The `rportfwd` command allows the user to open a local port on the Mythic server such that any traffic received on that port will be forwarded to the service specified by the IP and port routed through the computer the machine was ran on.