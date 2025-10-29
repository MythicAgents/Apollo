# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.4.3] - 2025-10-29

### Changed

- Updated PyPi package to v0.6.6

## [v2.4.2] - 2025-10-28

### Changed

- Updated PyPi Version to allow build parameters to specify ui position

## [v2.4.1] - 2025-10-27

### Changed

- Updated PyPi version
- Merged in hotfix for P2P comms missing messages sometimes

## [v2.4.0] - 2025-10-07

### Changed

- Updated to mythic-container==v0.6.0 for dynamic parameters
- Updated build parameters to hide shellcode parameters when output type is not shellcode
- Updated c2 deviations to hide get-based parameters that aren't used by this profile
- Updated make_token to allow blank passwords
- Updated ticket_store_purge to process `all` flag properly

## [v2.3.51] - 2025-09-12

## Changed

- Updated steal_token to report back the integrity level of the old and new token
- Updated steal_token to adjust the callback's integrity level 
- Updated rev2self to adjust the callback's integrity level

## [v2.3.50] - 2025-09-12

### Changed

- Fixed an issue with spawning processes after doing a `steal_token`
  - it was using the primary token instead of the impersonated identity
  
## [v2.3.49] - 2025-09-10

### Changed

- Updated apollo's `ls` functionality to check if a path ends in `:` and update it to `:\` instead
  - this fixes an issue with windows resolving `C:` as the current working directory compared to `C:\`
  
## [v2.3.48] - 2025-08-25

### Changed

- Fixed parsing for kerberos tickets in ticket_store_add 

## [v2.3.47] - 2025-08-21

### Changed

- Updated the parsing for kerberos tickets via impacket to handle missing time values in tickets

## [v2.3.46] - 2025-08-19

### Changed

- Updated inline_assembly to check thread execution with timeouts to be able to detect kill jobs for threads better
- Updated execute_pe to just report back process exit instead of misleading error codes

## [v2.3.45] - 2025-08-11

### Changed

- Fixed a bug in Apollo's P2P code where queued messages could pile up and not get sent

## [v2.3.44] - 2025-07-24

### Changed

- Updated reg_write_value to split input on new lines for multiline input types

## [v2.3.43] - 2025-07-24

### Changed

- Updated reg_write_value to allow you to specify the type of data to write
- Updated screenshot and screenshot_inject to not send extra file_ids to user output since PutFile does that automaically

## [v2.3.42] - 2025-07-24

### Changed

- Updated the screenshot_inject processing to use donut PyPi package

## [v2.3.41] - 2025-07-18

### Changed

- Updated the file upload messages to show chunk status and bail out on errors
- Updated the status for execute_coff and execute_assembly to be more informative

## [v2.3.40] - 2025-07-17

### Changed

- Fixed an issue with upload via file browser not respecting pathing

## [v2.3.39] - 2025-07-15

### Changed

- Fixed a bug with ls-ing UNC paths via the file browser for alternative hosts

## [v2.3.38] - 2025-07-15

### Changed

- Updated `socks` and `rpfwd` tasks to auto-issue `sleep 0` tasks when starting
- Updated `socks` task to auto-issue `sleep 1` when stopping
- Updated `socks` and `rpfwd` task display parameters
- Updated `jobkill` display parameters to be more meaningful
- Updated `jump_psexec` output to make sc output prettier
- Updated `powerpick`, `execute_assembly`, and `execute_pe` to check for sacrificial process pid > 0 rather than exit
  - this fixes a bug where access denied when spawning would lock when trying to kill a non-existent pid
- Updated logic in high integrity to only list out ticket cache values for current logon if no luid specified
- Updated ticket_cache_list to report back the current LUID even if there are no tickets available
  - Updated the associated browser script to account for this
  
## [v2.3.37] - 2025-07-14

### Changed

- Fixed a small bug in make_token output that was repeating the old token claims instead of the new ones
- Fixed the same bug in steal_token output

## [v2.3.36] - 2025-07-11

### Changed

- Updated wmiexecute to try two different ways of impersonating user context for remote execution
- Added CoInitializeSecurity call into apollo main program

## [v2.3.35] - 2025-07-11

### Changed

- Updated display params for wmiexecute
- Updated display params for ticket_cache_list

## [v2.3.34] - 2025-07-10

### Changed

- Fixing keylog_inject
  - adding keylog_inject browser script to go with it for basic conversion
  
## [v2.3.33] - 2025-07-10

### Changed

- Added a new interface function to update the Agent UUID
  - Used this interface in HTTP and Websocket profiles
  - Updated `unlink` command to leverage this for properly reflecting unlinked agents
- Fixed an issue in P2P code that wouldn't update P2P UUID after negotiating

## [v2.3.32] - 2025-07-08

### Changed

- Updated the help for the ticket commands
- Updated the error message for ticket_cache_extract
- Updated the completion function for ticket_cache_extract

## [v2.3.31] - 2025-07-07

### Changed

- Updated the processing for ticket_cache_list to better account for high/medium context
- Updated wmiexecute error code to be in hex not int
- Updated WebSocketClient code to reconnect on disconnect and added a few more checks for Proxy configs

## [v2.3.30] - 2025-07-03

### Changed

- Updated execute_coff, execute_assembly, inline_assembly, execute_pe, inline_assembly, and assembly_inject
  - these no longer require `register_*` commands and will automatically fetch the file if needed first

## [v2.3.29] - 2025-06-23

### Changed

- Updated `cd` callback information to get the new proper directory instead of what the user supplied

## [v2.3.28] - 2025-06-19

### Changed

- Updated the make_token and steal_token commands to report back Auth status, Auth Package, and Claims per token

## [v2.3.27] - 2025-06-17

### Changed

- Updated the build for COFFLoader.dll

## [v2.3.26] - 2025-06-17

### Changed

- Updated apollo to support new cwd and impersonation_context fields
- Updated execute_coff to copy COFFLoader.dll instead of move it as needed

## [v2.3.25] - 2025-06-05

### Changed

- Fixed type mismatch for ProxyPort

## [v2.3.24] - 2025-06-05

### Changed

- Updated the parsing of CallbackHost/CallbackPort and ProxyHost/ProxyPort to be more reliable

## [v2.3.23] - 2025-05-29

### Changed

- Updated the file download to report back the file id sooner
- Updated download browser script to display media as the file is downloading
- Updated execute_coff and execute_assembly to have register_file as dependencies
- Updated execute_coff to call execute_file instead of execute_coff command

## [v2.3.22] - 2025-05-28

### Changed

- Updated a reference in the execute_pe task to not reference an exception name in the execute_assembly task

## [v2.3.21] - 2025-05-14

### Changed

- Updated the builder to include all commands when building a debug version of apollo
- Updated the p2p code to initializes the edges array so checks for edge lengths don't crash

## [v2.3.20] - 2025-04-29

### Changed

- Updated some kerberos ticket functions to return more detailed error messages

## [v2.3.19] - 2025-04-29

### Changed

- Updated the `rpfwd` implementation to send Mythic notifications about new connections, not just new data

## [v2.3.18] - 2025-04-29

### Changed

- Updated the `ticket_cache_add` call to return more error status information

## [v2.3.17] - 2025-04-28

### Changed

- Updated `rpfwd` to allow specifying a debug level to help with troubleshooting rpfwd issues
- Fixed the `debug` build option to properly respect user supplied c2 configuration options

## [v2.3.16] - 2025-04-10

### Changed

- Updated the processing for mimikatz credentials
- Updated sleep to not have JSON in the display parameters
- Updated error messages in sleep
- Updated execute_assembly display parameters
- Updated link .net command to test webshell connectivity first

## [v2.3.15] - 2025-04-02

### changed

- Fixed an issue with webshell linking

## [v2.3.14] - 2025-03-30

### Changed

- Fixed an issue with setting configuration options with `\` characters not getting properly escaped
- Updated PyPi package

## [v2.3.13] - 2025-03-24

### Changed

- Fixed an issue with the inject command trying to auto-issue a follow-on link for p2p-based shellcode

## [v2.3.12] - 2025-03-16

### Changed

- Added an action (stop/start) for the SOCKS command
- Added an option for username/password for rpfwd/socks command
- Added a check in jobkill for the rpfwd command to auto stop it from the Mythic side

## [v2.3.11] - 2025-03-16

### Changed

- Added a few more try/catch blocks for named pipe writes
- Fixed a compile bug with an out of scope variable

## [v2.3.10] - 2025-03-14

### Changed

- Added a few more try/catch blocks for named pipe writes to help with breaks

## [v2.3.9] - 2025-03-14

### Changed

- Updated `ticket_store_add` to not create a temp logon session to fetch ticket information
  - Instead, ticket information is fetched via impacket in the apollo container first and sent down with the task
  
## [v2.3.8] - 2025-03-12

### Changed

- Added `debug` build option

## [v2.3.7] - 2025-03-12

### Changed

- Added the ability to select already uploaded files as part of the register_* commands

## [v2.3.6] - 2025-03-12

### Changed

- Added `-p:DebugType=None -p:DebugSymbols=false` to all `dotnet build` commands
- Removed sRDI package as it wasn't used
- Standardized donut usage to all be with the donut binary and not partially with the donut PyPi package
- Updated ticket_[store|cache]_list commands to return structured JSON
- Added browser scripts for ticket_[store|cache]_list commands
- 
## [v2.3.5] - 2025-03-03

### Changed

- Fixed a bug in Apollo's named pipe server that would break on writes for immediate disconnects from clients

## [v2.3.4] - 2025-03-03

### Changed

- Fixed a bug in `ls` that would fail to return data about files/folders if apollo couldn't get full information
- Added a `getsystem` command
- Updated `execute_coff` to spin off a new thread and set the impersonation context on that thread

## [v2.3.3] - 2025-02-28

### Changed

- Removed unnecessary make_token reference from sleep

## [v2.3.2] - 2025-02-25

### Changed

- Removed RunOF and replaced it with TrustedSec's COFFLoader project
- Adjusted the execute_coff command to pack args instead of sending down a typed array
- Added a reflective loader for the COFFLoader.dll (with Claude)
- Updated execute_pe's remote loaded code to hook more exit functions and load files better (with Claude)

## [v2.3.1] - 2025-02-11

### Changed

- Fixed a bug in `upload` that would try to create a UNC path even if the supplied hostname was the same as the current host

## [v2.3.0] - 2025-02-10

### Changed

- Updated TCP and SMB profiles to function the same way
- Updated TCP and SMB profiles to use new TCP and SMB profile definitions
  - Message formats changed, so v2.3 apollo agents cannot link to v2.2 apollo agents
  - This change means that apollo TCP can link with Poseidon TCP

## [v2.2.25] - 2025-01-30

### Changed

- Fixed a bug with upload if remote_path wasn't specified causing regex to break
- Updated execute_coff to optionally take in a file at execution time to support forge
- Updated execute_assembly to optionally take in a file at execution time to support forge
- Updated inline_assembly to optionally take in a file at execution time to support forge

## [v2.2.24] - 2025-01-08

### Changed

- Updated the KerberosTicket storage to handle fetching the right ticket more reliably

## [v2.2.23] - 2025-01-08

### Changed

- Updated the ticket_ticket_list to provide the flag for filtering SYSTEM tickets instead of doing it by default
- Updated sleep to make Jitter an optional parameter

## [v2.2.21] - 2024-11-12

### Changed

- Added some options to the builder for specifying config options for donut
- Added an option to auto-adjust the final payload name based on the configured options

## [v2.2.20] - 2024-11-12

### Changed

- Updated powerpick and PowerShellHost to handle output the same way as execute_assembly and execute_pe
- Updated sacrificial process code to only star tasks for reading stdout/stderr for non-fork and run jobs
- Updated `ps` to include `update_deleted` and send all output at once so Mythic can update the process browser properly
- Updated `kill` to also support `process_browser:kill`

## [v2.2.19] - 2024-11-08

### Changed

- Updated execute_pe code to use named pipes for reading output
- Updated sacrificial process code to read stdout as well for commands like run
- Updated run/shell to read output and exit

## [v2.2.18] - 2024-10-16

### Changed

- Updated `sleep` to take named parameters
- Updated `wmiexecute` to include Evan's wmi execute with impersonation tokens work https://gist.github.com/EvanMcBroom/99ea88304faec38d3ed1deefd1aba6f9
- Updated `ls` to check for a CWD of a UNC path before returning bad data for the browser script to leverage
- Updated `upload` and `download` to also try to process a CWD of a UNC path when returning full paths for the file browser
- Added `host` field to return `upload` data to try to more accurately capture the host of where data is uploaded

## [v2.2.17] - 2024-10-04

### Changed

- updated execute_assembly injected stub to hopefully capture more output successfully

## [v2.2.16] - 2024-10-03

### Changed

- updated `jump_wmi` command
- added `jump_psexec` command
- added `Service` build option
- updated execute_assembly and sacrificial processes to hopefully capture more output consistently

## [v2.2.15] - 2024-09-27

### Changed

- Added in new `jump_wmi` command
- Updated `make_token` to allow cli args instead of just modal without registering new creds
- Updated sizes in ls browser script

## [v2.2.14] - 2024-09-24

### Changed

- Added in functionality to link to Arachne via webshell configuration

## [v2.2.13] - 2024-08-21

### Changed

- Added in functionality from Evan McBroom to handle impersonated tokens in some situations with wmiexecute

## [v2.2.12] - 2024-08-20

### Changed

- Fixed the ptr errors in net_localgroup and net_localgroup_member

## [v2.2.11] - 2024-08-19

### Changed

- Fixed an issue with keylogs coming in one keystroke at a time
- Fixed an issue with ps command_line having broken quotes
- Added rpfwd capabilities

## [v2.2.10] - 2024-08-15

### Changed

- Updated pth, mimikatz, dcsync to report as alias commands so load will work properly

## [v2.2.5] - 2024-05-10

### Changed

- Merged in Websocket PR
- Merged in ExecuteCOFF PR
- Added ticket_cache* commands for interacting with local kerberos tickets
- Added ticket_store_* commands for interacting with a local kerberos store within the agent
- Added wmi_execute command for executing WMI locally and remotely
- Fixed double quoting issue in some commands
- Fixed reg_write command
- Updated `shell` to execute `run` without spawning sub task
- Fixed jobs command
- Updated .NET version used
- Fixed SOCKS command performance and reliability