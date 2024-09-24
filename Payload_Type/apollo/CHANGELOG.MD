# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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