using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Text;
using System.Threading;

namespace PowerShellHost
{
    class CustomPowerShellHost : PSHost
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
        private CustomPSRHostRawUserInterface _rawUi = new CustomPSRHostRawUserInterface();

        public CustomPSHostUserInterface()
        {
            
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
}
