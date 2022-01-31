+++
title = "pth"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Create, Process Inject, Process Kill
{{% /notice %}}

## Summary
Use mimikatz's `sekurlsa::pth` module to spawn a new process with a user's Kerberos keys.

### Arguments
#### Domain
Domain that the specified user is part of.

#### User
Username for which you've obtained credential material for.

#### NTLM
NTLM password hash of the specified user.

#### AES128 (Optional)
The AES128 key of the user. Used for over pass the hash.

#### AES256 (Optional)
The AES256 key of the user. Used for over pass the hash.

#### Run (Optional)
Program to spawn using alternate credentials. Default: cmd.exe.

{{% notice info %}}
When choosing a program to spawn, consider whether or not you need the process to be long-lived. A process that spawns and exits immediately will not be a good candidate to perform `steal_token` against, for example, as the process will no longer exist when attempting to impersonate the credential material.
{{% /notice %}}

## Usage
```
pth -Domain [domain.local] -User [username] -NTLM [ntlm_hash_val] [-AES128 [aes_128_val] -AES256 [aes_256_val] -Run [cmd.exe]]
```

Example
```
pth -Domain contoso.local -User djhohnstein -NTLM 21BC7DCD88EE195ECF3728677A47815B
pth -Domain contoso.local -User djhohnstein -NTLM 21BC7DCD88EE195ECF3728677A47815B -Run powershell.exe
```


## MITRE ATT&CK Mapping

- T1550

### Resrouces
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
