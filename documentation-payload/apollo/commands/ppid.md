+++
title = "ppid"
chapter = false
weight = 103
hidden = false
+++

## Summary
Set the parent process to the specified process identifier for all post-exploitation jobs.

If the process ID specified is not the same as Apollo's session, this function call will fail. Moreover, there are some SEH exceptions I can't track down and they all stem from using impersonated tokens and attempting to spoof logons. Due to that fact, if you are using an impersonated security context in any capacity, Apollo will default back to the current executing process for its parent. I have attempted to put as many guard rails as possible on this, but I'm certain I've missed some edge cases. Careful!

## Usage
```
ppid [pid]
```