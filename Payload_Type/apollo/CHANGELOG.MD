# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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