+++
title = "ps"
chapter = false
weight = 103
hidden = false
+++

## Summary

List running processes. The default mode opens each process with
`PROCESS_QUERY_LIMITED_INFORMATION` and reports the details available with that
access. A process that cannot be opened still appears with its PID and name when
those values are available.

- **Needs Admin:** False
- **Version:** 4

## Usage

```
ps
ps --extended
```

`--extended` additionally reads parent PIDs and command lines through
`NtQueryInformationProcess`, then reads window titles and executable file
version metadata. It uses the same limited-access process handle as the
default mode. Command-line information class 60 is undocumented, so that
field may be empty on Windows versions where the query is unavailable.
Fields may also be empty when access is denied or a process exits during listing.

The default output includes the PID, process name, session ID, architecture,
executable path, user, and integrity level where available. Fields that require
extended mode retain their empty or unknown values in the process response
schema. The `signer` field remains empty because file company metadata does
not verify a digital signature.

Safe handles close process and token handles after use. The
listing supports cancellation and returns the entries collected so far.
