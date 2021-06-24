+++
title = "golden_ticket"
chapter = false
weight = 103
hidden = true
+++

## Summary
Forge a golden/silver ticket using Mimikatz.

### Arguments (Popup)

#### Domain
The domain name. Must be FQDN.

#### SID
The domain SID (S-1-5-21-...).

#### User
The name of the target account.

#### ID
The RID of the target account.
Optional argument.

#### Groups
Comma-seperated list of group RIDs - no spaces.
Optional argument.

#### Key Type
The key type - must be RC4, AES128 or AES256.

#### Key
The key for the KRBTGT account, or for a service account for silver tickets.

#### Target
Target name (for silver tickets only - leave blank for golden tickets).
Optional argument.

#### Service
Service name (for silver tickets only - leave blank for golden tickets)
Optional argument.

#### Start Offset
Start time offset for the ticket in minutes from the current time.
Optional argument.

#### End In
Expiry time for the ticket from now in minutes - the default value should be 10 hours.
Optional argument.

#### Renew Max
Renewal time for the ticket from now in minutes - the default value should be 7 days.
Optional argument.

#### SIDs
Extra SIDs.
Used when traversing domain trusts.
Optional argument.

#### Sacrificial Logon
Specifies whether to create a sacrificial logon to avoid overwriting the ticket of the current user. The default value is True.

## Usage
```
golden_ticket
```

In the pop up menu
```
domain: [FQDN]
key: [krbtgt key]
key_type: [rc4 | aes128 | aes256]
sid: sid: [S-1-5-21-...]
user: [username]
```

Example
```
golden_ticket
```

In the pop up menu
```
domain: contoso.local
key: krbtgt key
key_type: aes256
sid: S-1-5-21-...
user: administrator
```

## Detailed Summary
The `golden_ticket` command is a wrapper around the `kerberos::golden` mimikatz command and therefore is using the same method and modified mimikatz dll used with the [`mimikatz`](/agents/apollo/commands/mimikatz/) command. This performs a golden/silver ticket attack by forging a kerberos ticket with the provided arguments and importing it into a logon session (pass the ticket). To avoid overwriting the current user's tickets, it is recommended to create a sacrificial logon session, which will result in a `Logon Type 9` logon event on the system.

{{% notice info %}}
A Process Create artifact is generated for this command.
{{% /notice %}}

### Resources
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
