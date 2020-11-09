+++
title = "cd"
chapter = false
weight = 103
hidden = false
+++

## Summary
Change the process's current working directory to a specified directory. This command accepts relative paths such as "..\" as well.

## Usage
```
cd [path to directory]
```
Example
```
cd C:\Users
```

## Detailed Summary
The `cd` command uses the `System.IO.Directory.SetCurrentDirectory` method to modify the process's current working directory to a specified directory. This command accepts relative paths, such as `..` or `..\..\Users`. Quotes are not needed when changing to directories with _spaces_ in their path name, such as `C:\Program Files`.

## Detailed Usage
Change to the root directory.
```
cd C:\
```
Change to the previous level directory.
```
cd ..
```
Change to a directory with spaces in name.
```
cd C:\Program Files
```
