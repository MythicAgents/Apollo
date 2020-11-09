+++
title = "jobs"
chapter = false
weight = 103
hidden = false
+++

## Summary
Retrieve a list of the agent's current running jobs. This list will not include `jobs` or `jobkill` related jobs.

## Usage
```
jobs
```

## Detailed Summary
The `jobs` command will retrieve a list of active running jobs, their parameters, and their associated process identifiers if the job required a sacrificial process.

![jobs](../images/jobs.png)