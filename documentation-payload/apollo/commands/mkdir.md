+++
title = "mkdir"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
Artifacts
- File Create
{{% /notice %}}

## Summary
Make a directory at the specified path.

### Arguments (Positional)
#### path
Path to the directory to create.

## Usage
```
mkdir [path]
```
Example
```
mkdir C:\config
```

## MITRE ATT&CK Mapping

- T1106

## Artifacts

- File Create

## Detailed Summary
The `mkdir` command uses the `System.IO.Directory.CreateDirectory` method to attempt to create a directory if the it does not already exist.