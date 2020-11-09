+++
title = "socks"
chapter = false
weight = 103
hidden = false
+++

## Summary
Start a SOCKS server to send traffic through your agent.

### Arguments (positional or modal popup)

#### action (required)
Must be one of `start` or `stop`

#### port (optional)
The port number to bind the Mythic SOCKSv5 server. Port is only required if the action is `start`.

## Usage
```
socks [action] [port]
```

Example
```
socks start 1234
```

## Detailed Usage
The `socks` command creates a SOCKS 5 compliant proxy on the agent so that network traffic can be proxied into the agent's network. The agent opens a bind connection on a random port between `65000` and `65535` and begins sending and receiving messages from the Mythic SOCKS server. Messages are exchanged at checkin so lower sleep times will increase SOCKS speed.
