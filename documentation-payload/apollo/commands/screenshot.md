+++
title = "screenshot"
chapter = false
weight = 103
hidden = true
+++

## Summary
Take a screenshot of the desktop session associated with the target process.

## Usage
```
screenshot [pid] [x86|x64]

screenshot (modal popup)
```

## MITRE ATT&CK Mapping

- T1113

## Detailed Summary
The `screenshot` command injects an unmanaged DLL, converted via sRDI, into the remote process specified in the arguments using the current injection technique. If you have requisite privileges to inject into other desktop sessions, this allows for taking screenshots in desktop sessions you are not currently running in.

## Author Information
Reznok rewrote this module from the ground up, and it's leagues better from its original implementation. You can find him at the following:

Social | Handle
-------|-------
Github|https://github.com/reznok
Twitter|[@reznok](https://twitter.com/rezn0k)
BloodHoundGang Slack|@reznok