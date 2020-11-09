//#define POWERPICK

using System;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.AccessControl;
using System.Text;
using System.Globalization;
using System.Threading;
using IPC;
using System.IO;




// Inject this assembly into the sacrificial process
namespace PowerShellRunner
{
    public class Program
    {
        static BinaryFormatter bf = new BinaryFormatter();
        public static NamedPipeServerStream CreateNamedPipeServer(string pipeName)
        {
            PipeSecurity pipeSecurityDescriptor = new PipeSecurity();
            PipeAccessRule everyoneAllowedRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            PipeAccessRule networkDenyRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Deny);       // This should only be used locally, so lets limit the scope
            pipeSecurityDescriptor.AddAccessRule(everyoneAllowedRule);
            pipeSecurityDescriptor.AddAccessRule(networkDenyRule);

            // Gotta be careful with the buffer sizes. There's a max limit on how much data you can write to a pipe in one sweep. IIRC it's ~55,000, but I dunno for sure.
            NamedPipeServerStream pipeServer = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 10, PipeTransmissionMode.Byte, PipeOptions.None, 32768, 32768, pipeSecurityDescriptor);

            return pipeServer;
        }

        public static PowerShellJobMessage ReadJob(NamedPipeServerStream pipeServer)
        {
            // Method 1
            var message = (PowerShellJobMessage)bf.Deserialize(pipeServer);
            return message;

        }


        public static void InitializeNamedPipeServer(string pipeName)
        {
            //var pipeName = "Apollo-PS";
            bf.Binder = new PowerShellJobMessageBinder();
            NamedPipeServerStream pipeServer = null;

            try
            {
                pipeServer = CreateNamedPipeServer(pipeName);
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: Could not start named pipe server. " + e.Message);
            }

            if (pipeServer == null)
                KillJob(JobExitCode.PipeStartError);

            PowerShellJobMessage newJob = null;
            try
            {
                // We shouldn't need to go async here since we'll only have one client, the agent core, and it'll maintain the connection to the named pipe until the job is done
                pipeServer.WaitForConnection();

                newJob = ReadJob(pipeServer);

            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: Could not read powershell from named pipe. " + e.Message);
                pipeServer.Close();
                return;
            }

            // Create new named pipe with task ID as name
            // This ensures that we don't collide with other jobs that might try to use this pipe name

            if (newJob == null)
                KillJob(JobExitCode.AssemblyReadError);

            using (StreamWriter writer = new StreamWriter(pipeServer))
            {
                writer.AutoFlush = true;


                // commented out for powerpick testing
                #if !POWERPICK
                var origStdout = Console.Out;
                var origStderr = Console.Error;

                Console.SetOut(writer);
                Console.SetError(writer);
                #endif
                try
                {
                    CustomPSHost host = new CustomPSHost();

                    InitialSessionState state = InitialSessionState.CreateDefault();
                    state.AuthorizationManager = null;

                    using (Runspace runspace = RunspaceFactory.CreateRunspace(host, state))
                    {
                        runspace.Open();

                        using (Pipeline pipeline = runspace.CreatePipeline())
                        {
                            pipeline.Commands.AddScript(newJob.LoadedScript);
                            pipeline.Commands.AddScript(newJob.Command);
                            pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                            pipeline.Commands.Add("Out-Default");
                            
                            pipeline.Invoke();
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: Unhandled exception in the PowerShellRunner: {0}\n{1}", e.Message, e.StackTrace);
                    //Console.WriteLine(e);
                }
                finally
                {
                    // for powerpick.
#if POWERPICK
                    bf.Serialize(pipeServer, new PowerShellTerminatedMessage()
                    {
                        Message = "Finished execution."
                    });
#else
                    // commented out for powerpick
                    // Restore streams... probably don't need to do this but meh
                    Console.SetOut(origStdout);
                    Console.SetError(origStderr);
#endif
                }

                pipeServer.WaitForPipeDrain();
            }

            //Console.WriteLine("Waiting for output to be read completely...");
            //Console.WriteLine("Exiting loader stub...");
        }


        static void Main(string[] args)
        {
        }

        private static void KillJob(JobExitCode exitCode)
        {
            Environment.Exit((int)exitCode);
        }
    }
}



class CustomPSHost : PSHost
{
    private Guid _hostId = Guid.NewGuid();
    private CustomPSHostUserInterface _ui = new CustomPSHostUserInterface();

    public override Guid InstanceId
    {
        get { return _hostId; }
    }

    public override string Name
    {
        get { return "ConsoleHost"; }
    }

    public override Version Version
    {
        get { return new Version(1, 0); }
    }

    public override PSHostUserInterface UI
    {
        get { return _ui; }
    }


    public override CultureInfo CurrentCulture
    {
        get { return Thread.CurrentThread.CurrentCulture; }
    }

    public override CultureInfo CurrentUICulture
    {
        get { return Thread.CurrentThread.CurrentUICulture; }
    }

    public override void EnterNestedPrompt()
    {
        throw new NotImplementedException("EnterNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override void ExitNestedPrompt()
    {
        throw new NotImplementedException("ExitNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override void NotifyBeginApplication()
    {
        return;
    }

    public override void NotifyEndApplication()
    {
        return;
    }

    public override void SetShouldExit(int exitCode)
    {
        return;
    }
}

class CustomPSHostUserInterface : PSHostUserInterface
{
    // Replace StringBuilder with whatever your preferred output method is (e.g. a socket or a named pipe)
    private StringBuilder _sb;
    private CustomPSRHostRawUserInterface _rawUi = new CustomPSRHostRawUserInterface();

    public CustomPSHostUserInterface()
    {
        //_writer = writer;
    }

    public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
    {
        Console.Write(value);
    }

    public override void WriteLine()
    {
        Console.WriteLine();
    }

    public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
    {
        Console.WriteLine(value);
    }

    public override void Write(string value)
    {
        Console.Write(value);
    }

    public override void WriteDebugLine(string message)
    {
        Console.WriteLine("DEBUG: " + message);
    }

    public override void WriteErrorLine(string value)
    {
        Console.WriteLine("ERROR: " + value);
    }

    public override void WriteLine(string value)
    {
        Console.WriteLine(value);
    }

    public override void WriteVerboseLine(string message)
    {
        Console.WriteLine("VERBOSE: " + message);
    }

    public override void WriteWarningLine(string message)
    {
        Console.WriteLine("WARNING: " + message);
    }

    public override void WriteProgress(long sourceId, ProgressRecord record)
    {
        return;
    }

    //public string Output
    //{
    //    get { return _writer.ToString(); }
    //}

    public override Dictionary<string, PSObject> Prompt(string caption, string message, System.Collections.ObjectModel.Collection<FieldDescription> descriptions)
    {
        throw new NotImplementedException("Prompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override int PromptForChoice(string caption, string message, System.Collections.ObjectModel.Collection<ChoiceDescription> choices, int defaultChoice)
    {
        throw new NotImplementedException("PromptForChoice is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
    {
        throw new NotImplementedException("PromptForCredential1 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
    {
        throw new NotImplementedException("PromptForCredential2 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override PSHostRawUserInterface RawUI
    {
        get { return _rawUi; }
    }

    public override string ReadLine()
    {
        throw new NotImplementedException("ReadLine is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override System.Security.SecureString ReadLineAsSecureString()
    {
        throw new NotImplementedException("ReadLineAsSecureString is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }
}

class CustomPSRHostRawUserInterface : PSHostRawUserInterface
{
    // Warning: Setting _outputWindowSize too high will cause OutOfMemory execeptions.  I assume this will happen with other properties as well
    private Size _windowSize = new Size { Width = 120, Height = 100 };

    private Coordinates _cursorPosition = new Coordinates { X = 0, Y = 0 };

    private int _cursorSize = 1;
    private ConsoleColor _foregroundColor = ConsoleColor.White;
    private ConsoleColor _backgroundColor = ConsoleColor.Black;

    private Size _maxPhysicalWindowSize = new Size
    {
        Width = int.MaxValue,
        Height = int.MaxValue
    };

    private Size _maxWindowSize = new Size { Width = 100, Height = 100 };
    private Size _bufferSize = new Size { Width = 100, Height = 1000 };
    private Coordinates _windowPosition = new Coordinates { X = 0, Y = 0 };
    private String _windowTitle = "";

    public override ConsoleColor BackgroundColor
    {
        get { return _backgroundColor; }
        set { _backgroundColor = value; }
    }

    public override Size BufferSize
    {
        get { return _bufferSize; }
        set { _bufferSize = value; }
    }

    public override Coordinates CursorPosition
    {
        get { return _cursorPosition; }
        set { _cursorPosition = value; }
    }

    public override int CursorSize
    {
        get { return _cursorSize; }
        set { _cursorSize = value; }
    }

    public override void FlushInputBuffer()
    {
        throw new NotImplementedException("FlushInputBuffer is not implemented.");
    }

    public override ConsoleColor ForegroundColor
    {
        get { return _foregroundColor; }
        set { _foregroundColor = value; }
    }

    public override BufferCell[,] GetBufferContents(Rectangle rectangle)
    {
        throw new NotImplementedException("GetBufferContents is not implemented.");
    }

    public override bool KeyAvailable
    {
        get { throw new NotImplementedException("KeyAvailable is not implemented."); }
    }

    public override Size MaxPhysicalWindowSize
    {
        get { return _maxPhysicalWindowSize; }
    }

    public override Size MaxWindowSize
    {
        get { return _maxWindowSize; }
    }

    public override KeyInfo ReadKey(ReadKeyOptions options)
    {
        throw new NotImplementedException("ReadKey is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
    }

    public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill)
    {
        throw new NotImplementedException("ScrollBufferContents is not implemented");
    }

    public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
    {
        throw new NotImplementedException("SetBufferContents is not implemented.");
    }

    public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
    {
        throw new NotImplementedException("SetBufferContents is not implemented");
    }

    public override Coordinates WindowPosition
    {
        get { return _windowPosition; }
        set { _windowPosition = value; }
    }

    public override Size WindowSize
    {
        get { return _windowSize; }
        set { _windowSize = value; }
    }

    public override string WindowTitle
    {
        get { return _windowTitle; }
        set { _windowTitle = value; }
    }
}
