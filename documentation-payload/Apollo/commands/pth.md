+++
title = "pth"
chapter = false
weight = 103
hidden = true
+++

## Summary
Perform pass-the-hash using an RC4 hash to impersonate a user.

### Arguments (Popup)
#### Credential
The credential to use for pass-the-hash. This must be from Mythic's credential store.

#### Program to Spawn
The application to execute as the user to impersonate the access token.

## Usage
```
pth
```

In the pop up menu
```
credential: [drop down menu of credentials]
program: [program to run]
```

Example
```
pth
```

In the pop up menu
```
credential: user - hash
program: cmd.exe
```

## Detailed Summary
The `pth` command is a wrapper around the `sekurlsa::pth` mimikatz command and therefore is using the same method and modified mimikatz dll used with the [`mimikatz`](/agents/apollo/commands/mimikatz/) command. This performs a pass-the-hash attack by starting a program as another user with bogus credentials, then patching `lsass.exe` with the provided hash to authenticate as that user on the network. This is similiar in functionality to using the `runas.exe` command with the `/netonly` argument, ultimately creating a `Logon Type 9` logon event on the system.

{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}

### Resources
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
