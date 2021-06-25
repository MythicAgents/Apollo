+++
title = "pwd"
chapter = false
weight = 103
hidden = true
+++

## Summary
Retrieve the agent process's current working directory.

## Usage
```
pwd
```
Example
```
pwd
```
## MITRE ATT&CK Mapping

- T1083

## Detailed Summary
The `pwd` command uses the `System.IO.Directory.GetCurrentDirectory` method to get the current working directory of the agent's process.
