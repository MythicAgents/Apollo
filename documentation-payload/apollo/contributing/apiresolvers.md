+++
title = "Creating API Resolvers"
chapter = false
weight = 25
+++

## Creating a New API Resolver

New API resolvers must be a new .NET 4.0 Class library project under the Apollo solution. This new project should have a new class that follows the naming schema of `XxxxResolver` and inherits from the `IWin32ApiResolver` interface.

### IWin32ApiResolver

The `IWin32ApiResolver` must implement three functions (though only one of which is currently leveraged in the Apollo code base).

```
// The most important function to implement - used universally across the code base
T GetLibraryFunction<T>(
    Library library,
    string functionName,
    bool canLoadFromDisk = true,
    bool resolveForwards = true) where T : Delegate

T GetLibraryFunction<T>(
    Library library,
    short ordinal,
    bool canLoadFromDisk = true,
    bool resolveForwards = true) where T : Delegate

T GetLibraryFunction<T>(
    Library library,
    string functionHash,
    long key,
    bool canLoadFromDisk=true,
    bool resolveForwards = true) where T : Delegate
```

For the uninitiated, `T` is a generic typing of `Delegate`, meaning that `T` defines an arbitrary function prototype that the API resolver should marshal the resolved function pointer to. For a simple example, we can define a delegate like `CloseHandle` as the following:
```
private delegate void CloseHandle(IntPtr Handle)
```
Then, using the resolver, you could do something like the following:
```
    CloseHandle pCloseHandle = MyWin32ApiResolver.GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle")
```

Now, the variable `pCloseHandle` is a .NET function representing the `CloseHandle` native Win32 API call.

{{% notice info %}}
The implementation of GetLibraryFunction is truly only important in its first iteration where you specify the cleartext function name. The GetLibraryFunction overloads that use ordinals and function hashes exist as the DInvoke resolver leverages these parameters. If you choose not to implement them and simply raise an error, the agent will still function at this current junction (1/29/2022)
{{% /notice %}}