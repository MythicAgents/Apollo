+++
title = "Contributing"
chapter = true
weight = 25
pre = "<b>4. </b>"
+++

## Creating a New Profile

Profiles should be created in `Apollo/C2Profiles/ProfileName.cs`. The new profile class must inherit either the `Mythic.C2Profiles.BindConnectC2Profile` or the `Mythic.C2Profiles.ReverseConnectC2Profile`. These abstract classes have a set of functions you'll need your new profile class to implement in order for the agent to operate. Failing to implement these classes will cause the agent to fail compilation.

Once you've created your new profile, you'll need to add preprocessor definitions surrounding the body of your code. If your new profile was defined in `NewProfileName.cs`, it'd be of the following format:

```
#define C2PROFILE_NAME_UPPER

#if NEWPROFILENAME
... code for profile NewProfileName...
#endif
```
Lastly, you'll need to modify `Apollo.cs` and add preprocessor definitions in the `Main` function such that when Mythic builds a new Apollo payload with your new profile, it'll be stamped in at compile time. `Apollo.cs` should look of the following format:

```
#define C2PROFILE_NAME_UPPER
// ... imports ...
namespace Apollo
{
    class Apollo
    {

        [STAThread]
        static void Main(string[] args)
        {
#if HTTP
            DefaultProfile profile = new DefaultProfile();
#elif SMBSERVER
            SMBServerProfile profile = new SMBServerProfile();
#elif NEWPROFILENAME
            NewProfileName profile = new NewProfileName();
#else
#error NO VALID EGRESS PROFILE SELECTED
#endif

            Agent implant = new Agent(profile);
            implant.Start();
        }
    }

}
```

## Creating a New Command

### Command File

All commands live under `Apollo/CommandModules/CommandName.cs`. If you were to create a new command named `newcommand`, create the file `Apollo/CommandModules/NewCommand.cs` and have it be in the following format:

```
#define COMMAND_NAME_UPPER

#if NEWCOMMAND

// ... imports ...

namespace Apollo.CommandModules
{
    public class NewCommand
    {
        public static void Execute(Job job, Agent agent)
        {
            // code goes here
        }
    }
}
#endif
```

Command parameters can be accessed through the `job.Task.parameters` object which is a string of parameters. This is either JSON or straight command line depending on how command processing is done in your `command.py` file within the Apollo payload container.

Commands report output through the passed `Apollo.Jobs.Job` object. If you want to report a single object of output, you do `job.AddOutput(output)`. If the command has finished processing, you can do `job.SetComplete(output)` or `job.SetError(output)` respectively. Both of these will set the task to complete and remove it from the job queue. Adding any output after these commands will not be sent to the server. Once either is issued, you the task should return and stop executing. If the output of your job is reporting back a JSON blob, you'll be able to subsequently access that data through a browser script.

Lastly, if you implement an unmanaged command, you'll need to do pre-processing on the injected command to convert it to shellcode using sRDI or some other means. Unmanaged commands currently all use the `unmanaged_injection.js` browser script which renders straight text. The injected command should open a named pipe, Apollo should connect to the named pipe, and the job should add output on each new line of output.

### Adding to Task Dispatch

Lastly, to ensure the command can be dispatched by the agent, you'll need to go into the `Apollo/Tasks/Task.cs` and your new command into the TaskMap dictionary. After modification, it should be of the form:

```
public static Dictionary<string, string> TaskMap = new Dictionary<string, string>()
{
#if NEWCOMMAND
    { "newcommand", "NewCommand" },
#endif
```

## Updating Mimikatz

1. Begin by downloading the Mimikatz source for for the version you'd like to target. It is recommended to pull the source code from a [release](https://github.com/gentilkiwi/mimikatz/releases) rather than cloning the repository.

2. Next, back up the following items as they are components which facilitate Apollo's use of Mimikatz.
    * `Apollo\Payload_Type\Apollo\agent_code\mimikatz\MimikatzInteraction\*`
    * `Apollo\Payload_Type\Apollo\agent_code\mimikatz\mimikatz\apollo_smb_server.c`

3. After backing up those items, delete the Mimikatz directory, `Apollo\Payload_Type\Apollo\agent_code\mimikatz`, to remove the old version

4. Next, place the updated version of Mimikatz in the location you just deleted, making sure that the name of the directory is `mimikatz` and does not contain any version numbers

5. Replace Apollo's components that were backed up in step 2

6. Open Mimikatz in Visual Studio by double clicking `Apollo\Payload_Type\Apollo\agent_code\mimikatz\mimikatz.sln`
	* If you do not have the required MFCs, install them via the Visual Studio Installed by selecting `C++ Windows XP Support for VS 2017 (v141) tools [Deprecated]` from the Individual Components menu 

7. In Visual Studio, right click on the `mimikatz` project, choose "Add", click "Existing Item", and select `apollo_smb_server.c` in the file explorer window

8. Right click on the `mimikatz` project again and choose "Properties", expand "C\C++" under "Configuration Properties", and change "Treat Warnings As Errors" to "No"

9. In the Visual Studio menu bar, change the Solution Configuration to "Simple_DLL" and the Architecture to "x64"

10. Compile the `mimikatz` project
    * This will create `Apollo\Payload_Type\Apollo\agent_code\mimikatz\x64\mimikatz.dll`

11. In the Visual Studio menu bar, change the Architecture to "Win32"

10. Compile the `mimikatz` project again
    * This will create `Apollo\Payload_Type\Apollo\agent_code\mimikatz\Win32\mimikatz.dll`

11. Replace the existing Mimikatz DLLs with the newly created ones, making sure to update the names to match their architecture
	* `mimikatz\x64\mimikatz.dll` -> `Apollo\agent_code\mimikatz_x64.dll`
	* `mimikatz\Win32\mimikatz.dll` -> `Apollo\agent_code\mimikatz_x86.dll`

12. Commit your changes to your development branch/fork

13. Reinstall Apollo using your development branch with `mythic-cli`
	* `sudo ./mythic-cli install github <url> <branch>`

14. After reinstalling Apollo, create a new payload through the Mythic web UI with at least the `exit` and `mimikatz` modules loaded and deploy it on a testing host

15. Run the `mimikatz` command with any module and validate that the compile time was updated in the banner