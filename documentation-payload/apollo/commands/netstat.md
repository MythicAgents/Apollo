+++
title = "netstat"
chapter = false
weight = 103
hidden = false
+++

## Summary
Task an agent to retrieve network connections.

### Arguments

The `netstat`has multiple boolean flags to filter what data gets returned. 

- `-Tcp`
- `-Udp`
- `-Listen`
- `-Established`

#### Tcp (optional)
Only return TCP results.

#### Udp (optional)
Only return UDP results.

#### Listen (optional)
Only return results that have a TCP state of `Listen`.

#### Established (optional)
Only return results that have a TCP state of `Established`.

## Usage
```
netstat
```

## Detailed Summary
The `netstat` command uses the Win32 API calling `GetExtendedTcpTable` and `GetExtendedUdpTable` from `iphlpapi.dll` to retrieve netstat. 
