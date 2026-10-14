// Only the surface required by run.Start and the abstract Process is modeled here.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace ApolloInterop.Interfaces
{
    public interface IMythicMessage { }
    public interface IAgent
    {
        FakeProcessManager GetProcessManager();
        FakeTaskManager GetTaskManager();
        FakeApi GetApi();
    }
}

namespace ApolloInterop.Classes.Api
{
    public enum Library { NTDLL }
}

namespace ApolloInterop.Structs.ApolloStructs
{
    public struct ApolloLogonInformation { }
}

namespace ApolloInterop.Structs.MythicStructs
{
    public sealed class MythicTask
    {
        public string Parameters;
    }

    public sealed class MythicTaskResponse
    {
        public object UserOutput;
        public bool Completed;
        public string Status;
        public Artifact[] Artifacts;
    }

    // Mirrors the production ProcessCreate formatting; not the full Mythic message model.
    public sealed class Artifact : IMythicMessage
    {
        public string BaseArtifact;
        public string ArtifactDetails;
        public int ProcessId;
        public string Application;
        public string Arguments;

        public static Artifact ProcessCreate(int pid, string application, string arguments = null)
        {
            return new Artifact
            {
                BaseArtifact = "ProcessCreate",
                ArtifactDetails = string.IsNullOrEmpty(arguments)
                    ? $"Started {application} (PID: {pid})"
                    : $"Started {application} {arguments} (PID: {pid})",
                ProcessId = pid,
                Application = application,
                Arguments = arguments
            };
        }
    }
}

namespace ApolloInterop.Classes
{
    public abstract class Tasking
    {
        protected readonly IAgent _agent;
        protected readonly MythicTask _data;
        protected static readonly ContractSerializer _jsonSerializer = new ContractSerializer();
        protected readonly CancellationTokenSource _cancellationToken = new CancellationTokenSource();

        protected Tasking(IAgent agent, MythicTask data)
        {
            _agent = agent;
            _data = data;
        }

        public abstract void Start();

        protected MythicTaskResponse CreateTaskResponse(object output, bool completed,
            string status = null, IEnumerable<IMythicMessage> messages = null)
        {
            return new MythicTaskResponse
            {
                UserOutput = output,
                Completed = completed,
                Status = status,
                Artifacts = messages == null ? Array.Empty<Artifact>() : messages.Cast<Artifact>().ToArray()
            };
        }
    }
}

// Use the same DataContractJsonSerializer and input encoding as Apollo's JsonSerializer.
public sealed class ContractSerializer
{
    public T Deserialize<T>(string json)
    {
        using (var stream = new MemoryStream(Encoding.Unicode.GetBytes(json)))
            return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(stream);
    }
}

public sealed class FakeAgent : IAgent
{
    public readonly FakeProcessManager Processes;
    public readonly FakeTaskManager Tasks = new FakeTaskManager();
    public FakeAgent() { Processes = new FakeProcessManager(this); }
    public FakeProcessManager GetProcessManager() => Processes;
    public FakeTaskManager GetTaskManager() => Tasks;
    public FakeApi GetApi() => throw new InvalidOperationException("Native API access is forbidden in this harness.");
}

public sealed class FakeApi
{
    public T GetLibraryFunction<T>(ApolloInterop.Classes.Api.Library library, string name)
        => throw new InvalidOperationException("Native API access is forbidden in this harness.");
}

public sealed class FakeTaskManager
{
    public readonly List<MythicTaskResponse> Responses = new List<MythicTaskResponse>();
    public void AddTaskResponseToQueue(MythicTaskResponse response) => Responses.Add(response);
}

public sealed class FakeProcessManager
{
    private readonly IAgent _agent;
    public int Calls;
    public string Application;
    public string Arguments;
    public FakeProcess Process;
    public FakeProcessManager(IAgent agent) { _agent = agent; }
    public Process NewProcess(string application, string arguments)
    {
        Calls++;
        Application = application;
        Arguments = arguments;
        Process = new FakeProcess(_agent, application, arguments);
        return Process;
    }
}

public sealed class FakeProcess : Process
{
    public int StartCalls;
    public FakeProcess(IAgent agent, string application, string arguments)
        : base(agent, application, arguments) { PID = 4242; }

    public override bool Start()
    {
        StartCalls++;
        HasExited = true;
        OnExit(this, EventArgs.Empty);
        return true;
    }

    public override void Kill() => throw new InvalidOperationException("Already exited fake process must not be killed.");
    public override bool Inject(byte[] code, string arguments = "") => throw new NotSupportedException();
    public override bool StartWithCredentials(ApolloInterop.Structs.ApolloStructs.ApolloLogonInformation info) => throw new NotSupportedException();
    public override bool StartWithCredentials(IntPtr token) => throw new NotSupportedException();
    public override void WaitForExit() => throw new NotSupportedException();
    public override void WaitForExit(int milliseconds) => throw new NotSupportedException();
}
