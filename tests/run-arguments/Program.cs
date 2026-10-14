using System;
using System.Linq;
using System.Text.Json;
using ApolloInterop.Structs.MythicStructs;

internal static class Program
{
    private static int _passed;

    private static int Main()
    {
        try
        {
            Success("plain arguments", "whoami.exe", "/all");
            Success("cmd plain arguments", "cmd.exe", "/c echo hello");
            Success("cmd embedded Command", "cmd.exe", "/c echo <Command>cmd.exe</Command>");
            Success("powershell outer cmd inner", "powershell.exe", "-NoProfile -Command \"Write-Output 'cmd.exe'\"");
            Success("shell alias plain", "cmd.exe", " /S /c whoami");
            Success("shell alias embedded cmd", "cmd.exe", " /S /c echo cmd.exe");
            Success("repeated executable in XML", "tool.exe",
                "--xml <root><exe>tool.exe</exe><again>tool.exe</again></root>");
            Success("repeated executable in script", "powershell.exe",
                "-Command \"Write-Output 'powershell.exe'; & powershell.exe -NoProfile\"");
            Success("quoted executable path retained", "\"C:\\Program Files\\Tools\\tool.exe\"", "--version");
            Success("null arguments", "tool.exe", null);
            Success("empty arguments", "tool.exe", "");
            Success("shell whitespace and inner executable", "cmd.exe",
                "  /c   \"C:\\Program Files\\Tools\\tool.exe\"  tool.exe\t  ");
            Success("quotes backslashes and whitespace", "tool.exe",
                " \t--path \"C:\\trailing\\\\\" --literal \\\"quoted\\\"\r\n  ");
            Error("null executable", Serialize(null, "--ignored"), "No executable passed.");
            Error("empty executable", Serialize("", "--ignored"), "No executable passed.");
            Error("missing executable field", "{\"arguments\":\"--ignored\"}", "No executable passed.");
            SuccessJson("missing arguments field", "tool.exe", null, "{\"executable\":\"tool.exe\"}");
            Error("null task parameters", null, "No command line arguments passed.");
            Error("empty task parameters", "", "No command line arguments passed.");
            Console.WriteLine($"PASS: {_passed} offline run.Start regression cases.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"FAIL: {error.Message}");
            return 1;
        }
    }

    private static string Serialize(string executable, string arguments)
        => JsonSerializer.Serialize(new { executable, arguments });

    private static void Success(string name, string executable, string arguments)
        => SuccessJson(name, executable, arguments, Serialize(executable, arguments));

    private static FakeAgent Run(string json)
    {
        var agent = new FakeAgent();
        new Tasks.run(agent, new MythicTask { Parameters = json }).Start();
        return agent;
    }

    private static void SuccessJson(string name, string executable, string arguments, string json)
    {
        var agent = Run(json);
        Equal(name, "NewProcess calls", 1, agent.Processes.Calls);
        Equal(name, "NewProcess application", executable, agent.Processes.Application);
        Equal(name, "NewProcess arguments", arguments, agent.Processes.Arguments);
        Equal(name, "Process application", executable, agent.Processes.Process.Application);
        string commandLine = string.IsNullOrEmpty(arguments) ? executable : executable + " " + arguments;
        Equal(name, "Process command line", commandLine, agent.Processes.Process.CommandLine);
        Equal(name, "Start calls", 1, agent.Processes.Process.StartCalls);
        Equal(name, "process exited", true, agent.Processes.Process.HasExited);
        Equal(name, "response count", 2, agent.Tasks.Responses.Count);
        Equal(name, "completion count", 1, agent.Tasks.Responses.Count(r => r.Completed));
        Equal(name, "error count", 0, agent.Tasks.Responses.Count(r => r.Status == "error"));
        var artifacts = agent.Tasks.Responses.SelectMany(r => r.Artifacts).ToArray();
        Equal(name, "artifact count", 1, artifacts.Length);
        var artifact = artifacts[0];
        Equal(name, "artifact type", "ProcessCreate", artifact.BaseArtifact);
        Equal(name, "artifact PID", 4242, artifact.ProcessId);
        Equal(name, "artifact application", executable, artifact.Application);
        Equal(name, "artifact arguments", arguments, artifact.Arguments);
        Equal(name, "artifact details", $"Started {commandLine} (PID: 4242)", artifact.ArtifactDetails);
        Pass(name);
    }

    private static void Error(string name, string json, string message)
    {
        var agent = Run(json);
        Equal(name, "NewProcess calls", 0, agent.Processes.Calls);
        Equal(name, "response count", 1, agent.Tasks.Responses.Count);
        var response = agent.Tasks.Responses[0];
        Equal(name, "completed", true, response.Completed);
        Equal(name, "status", "error", response.Status);
        Equal(name, "output", message, response.UserOutput);
        Equal(name, "artifact count", 0, response.Artifacts.Length);
        Pass(name);
    }

    private static void Equal<T>(string name, string field, T expected, T actual)
    {
        if (!object.Equals(expected, actual))
            throw new Exception($"{name}: {field}: expected {JsonSerializer.Serialize(expected)}, got {JsonSerializer.Serialize(actual)}");
    }

    private static void Pass(string name)
    {
        _passed++;
        Console.WriteLine($"PASS: {name}");
    }
}
