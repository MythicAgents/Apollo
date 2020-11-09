+++
title = "cp"
chapter = false
weight = 103
hidden = false
+++

## Summary
Copy a specified file to another location.

### Arguments (modal popup or positional)
#### destiantion
The path to copy a file too.

#### source
The path to the original file to be copied.

## Usage
```
cp [source] [dest]
```
Or, in the pop up menu
```
destination: [path to file]
source: [path to file]
```
Example
```
cp
```
In the pop up menu
```
destination: C:\config.txt
source: C:\Windows\Temp\config.txt
```

## Detailed Summary
The `cd` command uses the `System.IO.File.Copy` method to copy a file from a source path to a destination path. This command accepts UNC paths for file copies.

## Detailed Usage
Copy a file to a UNC path
```
cp
```
In the pop up menu
```
destination: C:\config.txt
source: \\server1\C$\Windows\Temp\config.txt
```
