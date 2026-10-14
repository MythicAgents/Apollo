# Offline `run` argument regressions

This dependency-free `net8.0` console project compiles the actual production
`Tasks/run.cs`, abstract `ApolloInterop/Classes/Core/Process.cs`, `IProcess`, and
`StringDataEventArgs`. `RUN` is defined for all configurations, including Release.
There are no NuGet package references; `NuGet.Config` clears package sources.

Each case invokes actual `run.Start()` with JSON parameters. `FakeProcessManager`
captures the exact application and arguments passed to `NewProcess`. Its process
uses the production base constructor for command-line assembly, but `Start()`
only marks itself exited and raises the exit event synchronously. No OS process,
Windows API, live agent, or Mythic service is started by the test code.

The 19 cases cover:

- Plain arguments.
- Repeated copies of the executable in XML and script arguments.
- An already-quoted executable path, retained exactly.
- Null, empty, and omitted arguments.
- Shell whitespace with an inner executable.
- Quotes, backslashes, tabs, spaces, and line breaks.
- Null, empty, and omitted executable fields: a completed error response and no process creation.
- Null and empty task parameters: a completed error response and no process creation.

Successful cases assert exact `NewProcess` fields, the production base process's
application/command line, immediate exit/completion, and one `ProcessCreate`
artifact with matching PID, application, arguments, and formatted details.
Assertions fail the console program with exit code 1.

## Run using the cached Apollo SDK image

With a local .NET 8 SDK, run from the repository root:

```sh
dotnet run --project tests/run-arguments/RunArguments.csproj --configuration Release
```

Alternatively, from the repository root with the image already cached:

```sh
docker run --rm --pull never --network none --entrypoint dotnet --user "$(id -u):$(id -g)" --env DOTNET_CLI_HOME=/tmp/dotnet-home --mount "type=bind,src=$PWD/tests/run-arguments,dst=/work/tests/run-arguments" --mount "type=bind,src=$PWD/Payload_Type/apollo/apollo/agent_code,dst=/work/Payload_Type/apollo/apollo/agent_code,readonly" ghcr.io/mythicagents/apollo:v0.1.0-rc4 run --project /work/tests/run-arguments/RunArguments.csproj --configuration Release
```

This uses the already-cached image (SDK 8.0.425), disables networking, replaces
the service entrypoint with `dotnet`, mounts only the tests and source, and builds
only this harness. The source mount is read-only. Generated `bin/` and `obj/`
files stay in the ignored test directories and are owned by the invoking user.
The image must already be cached; `--pull never` deliberately forbids downloading it.

Validated result: `PASS: 19 offline run.Start regression cases.` in Release.
Compiler warnings from the linked production source concern the lowercase `run`
type name and fields assigned by deserialization, not test failures.

## Scope and limitations

`Tasking`, `IAgent`, the task queue, native API surface, and Mythic message types
are deliberately minimal stubs, not full production implementations. The stub
serializer uses `DataContractJsonSerializer` with the same input encoding as
Apollo's serializer so `RunParameters`' actual `DataMember` names are exercised.
The artifact stub mirrors production `Artifact.ProcessCreate` formatting and
records its input fields for assertions; this does **not** test production Mythic
artifact serialization or full `Tasking.CreateTaskResponse` message routing.

The linked abstract `Process` constructor is tested, but concrete Windows process
creation, quoting interpretation by Windows, native calls, impersonation,
credentials, output streams, cancellation, failed starts, and asynchronous exit
ordering are not. Native API access and unsupported process operations throw if
accidentally reached. No full agent/payload build is performed. No production
helper or production source change is required by this harness.
