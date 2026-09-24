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
ps -extended
```

`-extended` additionally reads parent PIDs and command lines through
`NtQueryInformationProcess`, then reads window titles, executable file
version metadata, and the subject of an embedded signing certificate when
present. It uses the same limited-access process handle as the
default mode. Command-line information class 60 is undocumented, so that
field may be empty on Windows versions where the query is unavailable.
Fields may also be empty when access is denied or a process exits during listing.

The default output includes the PID, process name, session ID, architecture,
executable path, user, and integrity level where available. Fields that require
extended mode retain their empty or unknown values in the process response
schema. The `signer` field is the embedded certificate's subject when
available in extended mode. Catalog-signed files without an embedded
certificate leave it empty. The field is not a signature or trust verification.

Safe handles close process and token handles after use. The
listing supports cancellation and returns the entries collected so far.
