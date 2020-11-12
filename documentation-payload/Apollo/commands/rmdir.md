+++
title = "rmdir"
chapter = false
weight = 103
hidden = true
+++

## Summary
Remove a directory at the specified path.

### Arguments (positional)
#### path
Path to the directory to be deleted.

## Usage
```
rmdir [path]
```
Example
```
rmdir C:\config
```

## Detailed Summary
The `rmdir` command uses the `System.IO.Directory.Delete` method to attempt to delete the specified directory.

{{% notice info %}}
A Directory Delete artifact is generated from this command.
{{% /notice %}}