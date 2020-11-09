+++
title = "mkdir"
chapter = false
weight = 103
hidden = false
+++

## Summary
Make a directory at the specified path.

### Arguments (positional)
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

## Detailed Summary
The `mkdir` command uses the `System.IO.Directory.CreateDirectory` method to attempt to create a directory if the it does not already exist.
