+++
title = "API Resolvers"
chapter = false
weight = 102
+++

## Win32 API Resolution

At the time of writing this (1/29/2022), Apollo by default uses a single API resolver to resolve all native Win32 API calls it needs to perform its duties. This resolver is a simple resolver that first checks if the required module is currently loaded into the current process and, if not, loads it. Once the module is loaded it then calls `GetProcAddress` to get a pointer to the requested function.

However, there is a resolver that leverages the [DInvoke](https://github.com/TheWover/DInvoke) project to do all API resolution. Currently, there is no option to enable this from the UI or from agent tasking; however, in the future, this could be modifiable by an operator on build or during tasking. If one wanted to create their own custom API resolver outside of the two mentioned, see the [API Resolvers](/agents/apollo/contributing/apiresolvers/) documentation for how to contribute one.