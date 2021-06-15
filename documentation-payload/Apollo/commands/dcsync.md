+++
title = "dcsync"
chapter = false
weight = 103
hidden = true
+++

## Summary
Dump the credentials of a given account from a domain controller using the MS-DRSR protocol,

### Arguments (Popup)
#### Account Name
The name of the account that will be dumped.
Leave blank to dump all accounts.

#### Domain Name
The name of the domain of the account that will be dumped - must be a Fully Qualified Domain Name (FQDN).

#### Domain Controller
The name of the Domain Controller (DC) to target.

## Usage
```
dcsync {"DC":"dc to target","Domain":"fqdn","User":"account name"}
```

Example
```
dcsync {"DC":"dc.contoso.local","Domain":"contoso.local","User":"krbtgt"}
```

In the pop up menu
```
DC: [dc to target]
Domain: [fqdn]
User: [account name]
```

## Detailed Summary
The `dcsync` command is a wrapper around the `lsadump::dcsync` mimikatz command and therefore is using the same method and modified mimikatz dll used with the [`mimikatz`](/agents/apollo/commands/mimikatz/) command. This performs a dcsync attack by synchronizing account credentials fr>

{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}

### Resources
- [mimikatz](https://github.com/gentilkiwi/mimikatz)

