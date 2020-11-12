+++
title = "make_token"
chapter = false
weight = 103
hidden = true
+++

## Summary
Create a new logon session for the current thread with supplied credentials.

### Arguments (Popup)
#### credential
To use credentials, they must be inputted into Mythic's credential store. The credential store is populated either manually or from Mimikatz.

## Usage
```
make_token
```
Select credentials from drop down list.

## Detailed Summary
The `make_token` command uses `LogonUserA` Windows API to create a new logon session and apply it to the current thread. This logon session is created with a logon type `9` or new credentials. 
>A New Logon artifact is generated from thsi command.