+++
title = "jobkill"
chapter = false
weight = 103
hidden = true
+++

## Summary
Kill a running job for an agent.

## Usage (Positional)
```
jobkill [job id]
```
Example
```
jobkill 1
```

## Detailed Summary
The `jobkill` command kills a job first by respecting that job's custom `job.Kill()` method. Once returned, it'll abort the thread and any terminate the associated sacrificial process it's attached to (if any).