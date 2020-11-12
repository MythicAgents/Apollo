+++
title = "cat"
chapter = false
weight = 103
hidden = true
+++

## Summary

Print the contents of a file.

### Arguments (Positional)
#### path
Specify path to file to read contents

## Usage
```
cat [path]
```
Example
```
cat C:\config.txt
```

## Detailed Summary
The `cat` command uses the `System.IO.File.ReadAllText` method to create a handle to a specified file and read all the file's contents as a string. After reading, the handle to the file is closed and the gathered file contents are sent back to Mythic.
