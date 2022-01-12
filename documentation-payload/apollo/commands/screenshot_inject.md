+++
title = "screenshot"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Inject
{{% /notice %}}

## Summary
Take a screenshot of the desktop session associated with the target process.

## Arguments

### PID

The process to inject the screenshot assembly into.

### Count

How many screenshots to take. Default: 1

### Interval

Amount of time (in seconds) to wait between screenshots being taken. Default: 0

## Usage
```
screenshot_inject -PID [pid] -Count [count] -Interval [interval]
```

## MITRE ATT&CK Mapping

- T1113

## Special Thanks
Reznok wrote the Apollo 1.X version of this module. You can find him at the following:

Social | Handle
-------|-------
Github|https://github.com/reznok
Twitter|[@reznok](https://twitter.com/rezn0k)
BloodHoundGang Slack|@reznok