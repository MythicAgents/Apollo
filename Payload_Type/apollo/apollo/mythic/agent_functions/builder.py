import datetime
import time

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
import os, fnmatch, tempfile, sys, asyncio
from distutils.dir_util import copy_tree
from mythic_container.MythicGoRPC.send_mythic_rpc_callback_next_checkin_range import *
import traceback
import shutil
import json
import pathlib
import hashlib
import toml
from mythic_container.MythicRPC import *


def validate_httpx_config(config_data):
    """
    Validate httpx configuration to match C# HttpxConfig.Validate() logic.
    Returns None if valid, error message string if invalid.
    """
    valid_locations = ["cookie", "query", "header", "body", ""]
    valid_actions = ["base64", "base64url", "netbios", "netbiosu", "xor", "prepend", "append"]
    
    # Check name is required
    if not config_data.get("name"):
        return "Configuration name is required"
    
    # Check at least GET or POST must be configured
    get_config = config_data.get("get", {})
    post_config = config_data.get("post", {})
    
    get_uris = get_config.get("uris", [])
    post_uris = post_config.get("uris", [])
    
    if not get_uris and not post_uris:
        return "At least GET or POST URIs are required"
    
    # Validate each configured method (GET and POST only)
    variations = {
        "GET": get_config,
        "POST": post_config
    }
    
    for method, variation in variations.items():
        if not variation:
            continue
        
        # Check if method is actually configured
        is_configured = (
            variation.get("verb") or
            (variation.get("uris") and len(variation.get("uris", [])) > 0) or
            (variation.get("client") and (
                (variation["client"].get("headers") and len(variation["client"].get("headers", {})) > 0) or
                (variation["client"].get("parameters") and len(variation["client"].get("parameters", {})) > 0) or
                (variation["client"].get("transforms") and len(variation["client"].get("transforms", [])) > 0) or
                variation["client"].get("message", {}).get("location")
            )) or
            (variation.get("server") and (
                (variation["server"].get("headers") and len(variation["server"].get("headers", {})) > 0) or
                (variation["server"].get("transforms") and len(variation["server"].get("transforms", [])) > 0)
            ))
        )
        
        if not is_configured:
            continue
        
        # Validate URIs
        uris = variation.get("uris", [])
        if not uris or len(uris) == 0:
            return f"{method} URIs are required if {method} method is configured"
        
        # Validate message location and name
        client = variation.get("client", {})
        message = client.get("message", {})
        if message:
            location = message.get("location", "")
            if location not in valid_locations:
                return f"Invalid {method} message location: {location}"
            
            # Message name is required when location is not "body" or empty string
            if location and location != "body":
                if not message.get("name"):
                    return f"Missing name for {method} variation location '{location}'. Message name is required when location is 'cookie', 'query', or 'header'."
        
        # Validate client transforms
        client_transforms = client.get("transforms", [])
        for transform in client_transforms:
            action = transform.get("action", "").lower()
            if action not in valid_actions:
                return f"Invalid {method} client transform action: {transform.get('action')}"
            
            # Prepend/append transforms are not allowed when message location is "query"
            if message.get("location", "").lower() == "query" and action in ["prepend", "append"]:
                return (
                    f"{method} client transforms cannot use '{transform.get('action')}' when message location is 'query'. "
                    "Prepend/append transforms corrupt query parameter values because the server extracts only the parameter value "
                    "(without the parameter name), causing transform mismatches. Use prepend/append only for 'body', 'header', or 'cookie' locations."
                )
        
        # Validate server transforms
        server = variation.get("server", {})
        server_transforms = server.get("transforms", [])
        for transform in server_transforms:
            action = transform.get("action", "").lower()
            if action not in valid_actions:
                return f"Invalid {method} server transform action: {transform.get('action')}"
        
        # Validate encoding consistency: client and server must use matching base64/base64url encoding
        client_encoding = None
        for transform in client_transforms:
            action = transform.get("action", "").lower()
            if action in ["base64", "base64url"]:
                client_encoding = action
        
        server_encoding = None
        # Server transforms are applied in reverse order, so check from the end
        for transform in reversed(server_transforms):
            action = transform.get("action", "").lower()
            if action in ["base64", "base64url"]:
                server_encoding = action
                break
        
        # If both client and server have encoding transforms, they must match
        if client_encoding and server_encoding and client_encoding != server_encoding:
            return (
                f"{method} encoding mismatch: client uses {client_encoding} but server uses {server_encoding}. "
                "Client and server encoding transforms must match."
            )
    
    return None  # Validation passed


class Apollo(PayloadType):
    name = "apollo"
    file_extension = "exe"
    author = "@djhohnstein, @its_a_feature_"
    mythic_encrypts = True
    supported_os = [
        SupportedOS.Windows
    ]
    semver = "2.4.1"
    wrapper = False
    wrapped_payloads = ["scarecrow_wrapper", "service_wrapper"]
    c2_profiles = ["http", "httpx", "smb", "tcp", "websocket"]
    note = """
A fully featured .NET 4.0 compatible training agent. Version: {}. 
NOTE: P2P Not compatible with v2.2 agents! 
NOTE: v2.3.2+ has a different bof loader than 2.3.1 and are incompatible since their arguments are different
    """.format(semver)
    supports_dynamic_loading = True
    shellcode_format_options = ["Binary", "Base64", "C", "Ruby", "Python", "Powershell", "C#", "Hex"]
    shellcode_bypass_options = ["None", "Abort on fail", "Continue on fail"]
    supports_multiple_c2_instances_in_build = False
    supports_multiple_c2_in_build = False
    c2_parameter_deviations = {
        "http": {
            "get_uri": C2ParameterDeviation(
                supported=False,
                choices=[]  # Disabled parameter, but frontend expects array
            ),
            "query_path_name": C2ParameterDeviation(
                supported=False,
                choices=[]  # Disabled parameter, but frontend expects array
            ),
            #"headers": C2ParameterDeviation(supported=True, dictionary_choices=[
            #    DictionaryChoice(name="User-Agent", default_value="Hello", default_show=True),
            #    DictionaryChoice(name="HostyHost", default_show=False, default_value=""),
            #])
        }
    }
    build_parameters = [
        BuildParameter(
            name="output_type",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["WinExe", "Shellcode", "Service", "Source"],
            default_value="WinExe",
            description="Output as shellcode, executable, sourcecode, or service.",
        ),
        BuildParameter(
            name="shellcode_format",
            parameter_type=BuildParameterType.ChooseOne,
            choices=shellcode_format_options,
            default_value="Binary",
            description="Donut shellcode format options.",
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode")
            ]
        ),
        BuildParameter(
            name="shellcode_bypass",
            parameter_type=BuildParameterType.ChooseOne,
            choices=shellcode_bypass_options,
            default_value="Continue on fail",
            description="Donut shellcode AMSI/WLDP/ETW Bypass options.",
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode")
            ]
        ),
        BuildParameter(
            name="adjust_filename",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Automatically adjust payload extension based on selected choices.",
        ),
        BuildParameter(
            name="debug",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Create a DEBUG version.",
        ),
        BuildParameter(
            name="enable_keying",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable environmental keying to restrict agent execution to specific systems.",
            group_name="Keying Options",
        ),
        BuildParameter(
            name="keying_method",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["Hostname", "Domain", "Registry"],
            default_value="Hostname",
            description="Method of environmental keying.",
            group_name="Keying Options",
            hide_conditions=[
                HideCondition(name="enable_keying", operand=HideConditionOperand.NotEQ, value=True)
            ]
        ),
        BuildParameter(
            name="keying_value",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="The hostname or domain name the agent should match (case-insensitive). Agent will exit if it doesn't match.",
            group_name="Keying Options",
            hide_conditions=[
                HideCondition(name="enable_keying", operand=HideConditionOperand.NotEQ, value=True),
                HideCondition(name="keying_method", operand=HideConditionOperand.EQ, value="Registry")
            ]
        ),
        BuildParameter(
            name="registry_path",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="Full registry path (e.g., HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName)",
            group_name="Keying Options",
            hide_conditions=[
                HideCondition(name="enable_keying", operand=HideConditionOperand.NotEQ, value=True),
                HideCondition(name="keying_method", operand=HideConditionOperand.NotEQ, value="Registry")
            ]
        ),
        BuildParameter(
            name="registry_value",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="The registry value to check against.",
            group_name="Keying Options",
            hide_conditions=[
                HideCondition(name="enable_keying", operand=HideConditionOperand.NotEQ, value=True),
                HideCondition(name="keying_method", operand=HideConditionOperand.NotEQ, value="Registry")
            ]
        ),
        BuildParameter(
            name="registry_comparison",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["Matches", "Contains"],
            default_value="Matches",
            description="Matches (secure, hash-based) or Contains (WEAK, plaintext comparison). WARNING: Contains mode stores the value in plaintext!",
            group_name="Keying Options",
            hide_conditions=[
                HideCondition(name="enable_keying", operand=HideConditionOperand.NotEQ, value=True),
                HideCondition(name="keying_method", operand=HideConditionOperand.NotEQ, value="Registry")
            ]
        )
    ]
    agent_path = pathlib.Path(".") / "apollo" / "mythic"
    agent_code_path = pathlib.Path(".") / "apollo" / "agent_code"
    agent_icon_path = agent_path / "agent_functions" / "apollo.svg"
    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Copying files to temp location"),
        BuildStep(step_name="Compiling", step_description="Compiling with nuget and dotnet"),
        BuildStep(step_name="Donut", step_description="Converting to Shellcode"),
        BuildStep(step_name="Creating Service", step_description="Creating Service EXE from Shellcode")
    ]

    #async def command_help_function(self, msg: HelpFunctionMessage) -> HelpFunctionMessageResponse:
    #    return HelpFunctionMessageResponse(output=f"we did it!\nInput: {msg}", success=False)


    async def build(self) -> BuildResponse:
        # this function gets called to create an instance of your payload
        resp = BuildResponse(status=BuildStatus.Error)
        # debugging
        # resp.status = BuildStatus.Success
        # return resp
        #end debugging
        defines_commands_upper = ["#define EXIT"]
        if self.get_parameter('debug'):
            possibleCommands = await SendMythicRPCCommandSearch(MythicRPCCommandSearchMessage(
                SearchPayloadTypeName="apollo",
            ))
            if possibleCommands.Success:
                resp.updated_command_list = [c.Name for c in possibleCommands.Commands]
                defines_commands_upper = [f"#define {x.upper()}" for x in resp.updated_command_list]
        else:
            defines_commands_upper = [f"#define {x.upper()}" for x in self.commands.get_commands()]
        # Handle keying parameters
        enable_keying = self.get_parameter('enable_keying')
        keying_enabled = "true" if enable_keying else "false"
        keying_method_str = self.get_parameter('keying_method') if enable_keying else ""
        
        # Map keying method to numeric value for obfuscation
        # 0 = None, 1 = Hostname, 2 = Domain, 3 = Registry
        keying_method_map = {
            "Hostname": "1",
            "Domain": "2",
            "Registry": "3"
        }
        keying_method = keying_method_map.get(keying_method_str, "0")
        
        # Hash the keying value for security (force uppercase before hashing)
        keying_value_hash = ""
        registry_path = ""
        registry_value = ""
        registry_comparison = "0"  # Default to 0 for numeric field
        
        if enable_keying:
            if keying_method_str == "Registry":
                # Handle registry keying
                registry_path = self.get_parameter('registry_path') if self.get_parameter('registry_path') else ""
                registry_comparison_str = self.get_parameter('registry_comparison') if self.get_parameter('registry_comparison') else "Matches"
                
                # Map registry comparison to numeric value: 1 = Matches, 2 = Contains
                registry_comparison = "1" if registry_comparison_str == "Matches" else "2"
                
                registry_value_raw = self.get_parameter('registry_value') if self.get_parameter('registry_value') else ""
                
                if registry_comparison_str == "Matches":
                    # Hash the registry value for secure matching
                    if registry_value_raw:
                        plaintext_value = registry_value_raw.upper()
                        keying_value_hash = hashlib.sha256(plaintext_value.encode('utf-8')).hexdigest()
                elif registry_comparison_str == "Contains":
                    # Store plaintext for contains matching (weak security)
                    registry_value = registry_value_raw
            else:
                # Handle hostname/domain keying
                if self.get_parameter('keying_value'):
                    plaintext_value = self.get_parameter('keying_value').upper()
                    keying_value_hash = hashlib.sha256(plaintext_value.encode('utf-8')).hexdigest()
        
        special_files_map = {
            "Config.cs": {
                "payload_uuid": self.uuid,
                "keying_enabled": keying_enabled,
                "keying_method": keying_method,
                "keying_value_hash": keying_value_hash,
                "registry_path": registry_path,
                "registry_value": registry_value,
                "registry_comparison": registry_comparison,
            },
        }
        extra_variables = {

        }
        success_message = f"Apollo {self.uuid} Successfully Built"
        stdout_err = ""
        defines_profiles_upper = []
        compileType = "debug" if self.get_parameter('debug') else "release"
        buildPath = "Debug" if self.get_parameter('debug') else "Release"
        if len(set([info.get_c2profile()["is_p2p"] for info in self.c2info])) > 1:
            resp.set_status(BuildStatus.Error)
            resp.set_build_message("Cannot mix egress and P2P C2 profiles")
            return resp

        for c2 in self.c2info:
            profile = c2.get_c2profile()
            defines_profiles_upper.append(f"#define {profile['name'].upper()}")
            
            # Initialize all parameters with empty strings as defaults to ensure placeholders are replaced
            if profile['name'] == 'httpx':
                default_httpx_params = ['callback_interval', 'callback_jitter', 'callback_domains', 
                                        'domain_rotation', 'failover_threshold', 'encrypted_exchange_check',
                                        'killdate', 'raw_c2_config', 'proxy_host', 'proxy_port', 
                                        'proxy_user', 'proxy_pass', 'domain_front', 'timeout']
                for param in default_httpx_params:
                    prefixed_key = f"{profile['name'].lower()}_{param}"
                    if prefixed_key not in special_files_map.get("Config.cs", {}):
                        special_files_map.setdefault("Config.cs", {})[prefixed_key] = ""
            
            for key, val in c2.get_parameters_dict().items():
                prefixed_key = f"{profile['name'].lower()}_{key}"
                
                # Check for raw_c2_config file parameter FIRST before other type checks
                if key == "raw_c2_config" and profile['name'] == "httpx":
                    # Handle httpx raw_c2_config file parameter - REQUIRED for httpx profile
                    if not val or val == "":
                        resp.set_status(BuildStatus.Error)
                        resp.build_stderr = "raw_c2_config is REQUIRED for httpx profile. Please upload a JSON or TOML configuration file."
                        return resp
                    
                    try:
                        # Read configuration file contents
                        response = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(val))
                        
                        if not response.Success:
                            resp.set_status(BuildStatus.Error)
                            resp.build_stderr = f"Error reading raw_c2_config file: {response.Error}"
                            return resp
                        
                        raw_config_file_data = response.Content.decode('utf-8')
                        
                        # Try parsing the content as JSON first
                        try:
                            config_data = json.loads(raw_config_file_data)
                        except json.JSONDecodeError:
                            # If JSON fails, try parsing as TOML
                            try:
                                config_data = toml.loads(raw_config_file_data)
                            except Exception as toml_err:
                                resp.set_status(BuildStatus.Error)
                                resp.build_stderr = f"Failed to parse raw_c2_config as JSON or TOML: {toml_err}"
                                return resp
                        
                        # Validate the httpx configuration before building
                        validation_error = validate_httpx_config(config_data)
                        if validation_error:
                            resp.set_status(BuildStatus.Error)
                            resp.build_stderr = f"Invalid httpx configuration: {validation_error}"
                            return resp
                        
                        # Store the parsed config for Apollo to use
                        # Base64 encode to avoid C# string escaping issues
                        import base64
                        encoded_config = base64.b64encode(raw_config_file_data.encode('utf-8')).decode('ascii')
                        special_files_map["Config.cs"][prefixed_key] = encoded_config
                        
                    except Exception as err:
                        resp.set_status(BuildStatus.Error)
                        resp.build_stderr = f"Error processing raw_c2_config: {str(err)}"
                        return resp
                    
                    continue  # Skip to next parameter

                if isinstance(val, dict) and 'enc_key' in val:
                    if val["value"] == "none":
                        resp.set_status(BuildStatus.Error)
                        resp.set_build_message("Apollo does not support plaintext encryption")
                        return resp

                    # TODO: Prefix the AESPSK variable and also make it specific to each profile
                    special_files_map["Config.cs"][key] = val["enc_key"] if val["enc_key"] is not None else ""
                elif isinstance(val, list):
                    # Handle list values (like callback_domains as an array)
                    val = ', '.join(str(item) for item in val)
                
                # Now process as string if it's a string
                if isinstance(val, str):
                    # Check if the value looks like a JSON array string (e.g., '["domain1", "domain2"]')
                    if val.strip().startswith('[') and val.strip().endswith(']'):
                        try:
                            # Parse the JSON array and join with commas for Apollo
                            json_val = json.loads(val)
                            if isinstance(json_val, list):
                                # Join list items with commas
                                val = ', '.join(json_val)
                        except:
                            # If parsing fails, use as-is
                            pass
                    
                    escaped_val = val.replace("\\", "\\\\")
                    # Check for newlines in the string that would break C# syntax
                    if '\n' in escaped_val or '\r' in escaped_val:
                        stdout_err += f"  WARNING: String '{prefixed_key}' contains newlines! This will break C# syntax.\n"
                        # Replace newlines with escaped versions for C# strings
                        escaped_val = escaped_val.replace('\n', '\\n').replace('\r', '\\r')
                    special_files_map["Config.cs"][prefixed_key] = escaped_val
                elif isinstance(val, bool):
                    if key == "encrypted_exchange_check" and not val:
                        resp.set_status(BuildStatus.Error)
                        resp.set_build_message(f"Encrypted exchange check needs to be set for the {profile['name']} C2 profile")
                        return resp
                    special_files_map["Config.cs"][prefixed_key] = "true" if val else "false"
                elif isinstance(val, dict):
                    extra_variables = {**extra_variables, **val}
                else:
                    special_files_map["Config.cs"][prefixed_key] = json.dumps(val)
        
        try:
            # make a temp directory for it to live
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid)
            
            # shutil to copy payload files over
            copy_tree(str(self.agent_code_path), agent_build_path.name)
            
            # Get selected profiles from c2info
            selected_profiles = [c2.get_c2profile()['name'] for c2 in self.c2info]
            
            # Filter Apollo.csproj to include only selected profile projects
            csproj_path = os.path.join(agent_build_path.name, "Apollo", "Apollo.csproj")
            if os.path.exists(csproj_path):
                try:
                    filter_csproj_profile_references(csproj_path, selected_profiles)
                    
                    # Also filter Config.cs to remove #define statements for unselected profiles
                    config_path = os.path.join(agent_build_path.name, "Apollo", "Config.cs")
                    if os.path.exists(config_path):
                        filter_config_defines(config_path, selected_profiles)
                except Exception as e:
                    stdout_err += f"\nWarning: Failed to filter csproj references: {e}. Building with all profiles.\n"
            
            # first replace everything in the c2 profiles
            for csFile in get_csharp_files(agent_build_path.name):
                templateFile = open(csFile, "rb").read().decode()
                templateFile = templateFile.replace("#define C2PROFILE_NAME_UPPER", "\n".join(defines_profiles_upper))
                templateFile = templateFile.replace("#define COMMAND_NAME_UPPER", "\n".join(defines_commands_upper))
                for specialFile in special_files_map.keys():
                    if csFile.endswith(specialFile):
                        for key, val in special_files_map[specialFile].items():
                            placeholder = key + "_here"
                            if placeholder in templateFile:
                                templateFile = templateFile.replace(placeholder, val)
                        if specialFile == "Config.cs":
                            if len(extra_variables.keys()) > 0:
                                extra_data = ""
                                for key, val in extra_variables.items():
                                    extra_data += "                        { \"" + key + "\", \"" + val + "\" },\n"
                                templateFile = templateFile.replace("HTTP_ADDITIONAL_HEADERS_HERE", extra_data)
                            else:
                                templateFile = templateFile.replace("HTTP_ADDITIONAL_HEADERS_HERE", "")
                with open(csFile, "wb") as f:
                    f.write(templateFile.encode())
            
            # Determine if we need to embed the default config
            embed_default_config = True
            for c2 in self.c2info:
                profile = c2.get_c2profile()
                if profile['name'] == 'httpx':
                    raw_config = c2.get_parameters_dict().get('raw_c2_config', '')
                    if raw_config and raw_config != "":
                        embed_default_config = False
                        break
            
            output_path = f"{agent_build_path.name}/{buildPath}/Apollo.exe"
            
            # Build command with conditional embedding
            if self.get_parameter('debug'):
                command = f"dotnet build -c {compileType} -p:Platform=\"Any CPU\" -p:EmbedDefaultConfig={str(embed_default_config).lower()} -o {agent_build_path.name}/{buildPath}/ --verbosity quiet"
            else:
                command = f"dotnet build -c {compileType} -p:DebugType=None -p:DebugSymbols=false -p:DefineConstants=\"\" -p:Platform=\"Any CPU\" -p:EmbedDefaultConfig={str(embed_default_config).lower()} -o {agent_build_path.name}/{buildPath}/ --verbosity quiet"
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering Files",
                StepStdout="Found all files for payload",
                StepSuccess=True
            ))
            proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
            stdout, stderr = await proc.communicate()
            if stdout:
                stdout_err += f'\n[stdout]\n{stdout.decode()}\n'
            if stderr:
                stdout_err += f'[stderr]\n{stderr.decode()}' + "\n" + command

            # Check if dotnet build command succeeded
            if proc.returncode != 0:
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=f"dotnet build failed with exit code {proc.returncode}\nCommand: {command}\n{stdout_err}",
                    StepSuccess=False
                ))
                resp.status = BuildStatus.Error
                resp.payload = b""
                resp.build_message = f"dotnet build failed with exit code {proc.returncode}"
                resp.build_stderr = stdout_err
                return resp

            if os.path.exists(output_path):
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout="Successfully compiled payload",
                    StepSuccess=True
                ))
                resp.status = BuildStatus.Success
                targetExeAsmPath = "/srv/ExecuteAssembly.exe"
                targetPowerPickPath = "/srv/PowerShellHost.exe"
                targetScreenshotInjectPath = "/srv/ScreenshotInject.exe"
                targetKeylogInjectPath = "/srv/KeylogInject.exe"
                targetExecutePEPath = "/srv/ExecutePE.exe"
                targetInteropPath = "/srv/ApolloInterop.dll"
                shutil.move(f"{agent_build_path.name}/{buildPath}/ExecuteAssembly.exe", targetExeAsmPath)
                shutil.move(f"{agent_build_path.name}/{buildPath}/PowerShellHost.exe", targetPowerPickPath)
                shutil.move(f"{agent_build_path.name}/{buildPath}/ScreenshotInject.exe", targetScreenshotInjectPath)
                shutil.move(f"{agent_build_path.name}/{buildPath}/KeylogInject.exe", targetKeylogInjectPath)
                shutil.move(f"{agent_build_path.name}/{buildPath}/ExecutePE.exe", targetExecutePEPath)
                shutil.move(f"{agent_build_path.name}/{buildPath}/ApolloInterop.dll", targetInteropPath)
                if self.get_parameter('output_type') == "Source":
                    shutil.make_archive(f"/tmp/{agent_build_path.name}/source", "zip", f"{agent_build_path.name}")
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Donut",
                        StepStdout="Not converting to Shellcode through donut, passing through.",
                        StepSuccess=True
                    ))
                    resp.payload = open(f"/tmp/{agent_build_path.name}/source.zip", 'rb').read()
                    resp.build_message = success_message
                    resp.status = BuildStatus.Success
                    resp.build_stdout = stdout_err
                    resp.updated_filename = adjust_file_name(self.filename,
                                                             self.get_parameter("shellcode_format"),
                                                             self.get_parameter("output_type"),
                                                             self.get_parameter("adjust_filename"))
                    #need to cleanup zip folder
                    shutil.rmtree(f"/tmp/tmp")
                elif self.get_parameter('output_type') == "WinExe":
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Donut",
                        StepStdout="Not converting to Shellcode through donut, passing through.",
                        StepSuccess=True
                    ))
                    resp.payload = open(output_path, 'rb').read()
                    resp.build_message = success_message
                    resp.status = BuildStatus.Success
                    resp.build_stdout = stdout_err
                    resp.updated_filename = adjust_file_name(self.filename,
                                                             self.get_parameter("shellcode_format"),
                                                             self.get_parameter("output_type"),
                                                             self.get_parameter("adjust_filename"))
                else:
                    shellcode_path = "{}/loader.bin".format(agent_build_path.name)
                    donutPath = os.path.abspath(self.agent_code_path / "donut")
                    command = "chmod 777 {}; chmod +x {}".format(donutPath, donutPath)
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                                 stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await proc.communicate()
                    command = "{} -x3 -k2 -o loader.bin -i {}".format(donutPath, output_path)
                    if self.get_parameter('output_type') == "Shellcode":
                        command += f" -f{self.shellcode_format_options.index(self.get_parameter('shellcode_format')) + 1}"
                    command += f" -b{self.shellcode_bypass_options.index(self.get_parameter('shellcode_bypass')) + 1}"
                    # need to go through one more step to turn our exe into shellcode
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                                 stderr=asyncio.subprocess.PIPE,
                                                                 cwd=agent_build_path.name)
                    stdout, stderr = await proc.communicate()

                    stdout_err += f'[stdout]\n{stdout.decode()}\n'
                    stdout_err += f'[stderr]\n{stderr.decode()}'

                    # Check if donut command succeeded
                    if proc.returncode != 0:
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Donut",
                            StepStdout=f"Donut failed with exit code {proc.returncode}\nCommand: {command}\n{stdout_err}",
                            StepSuccess=False
                        ))
                        resp.build_message = f"Donut failed with exit code {proc.returncode}"
                        resp.status = BuildStatus.Error
                        resp.payload = b""
                        resp.build_stderr = stdout_err
                        return resp

                    if not os.path.exists(shellcode_path):
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Donut",
                            StepStdout=f"Failed to pass through donut:\n{command}\n{stdout_err}",
                            StepSuccess=False
                        ))
                        resp.build_message = "Failed to create shellcode"
                        resp.status = BuildStatus.Error
                        resp.payload = b""
                        resp.build_stderr = stdout_err
                    else:
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Donut",
                            StepStdout=f"Successfully passed through donut:\n{command}",
                            StepSuccess=True
                        ))
                        if self.get_parameter('output_type') == "Shellcode":
                            resp.payload = open(shellcode_path, 'rb').read()
                            resp.build_message = success_message
                            resp.status = BuildStatus.Success
                            resp.build_stdout = stdout_err
                            resp.updated_filename = adjust_file_name(self.filename,
                                                                     self.get_parameter("shellcode_format"),
                                                                     self.get_parameter("output_type"),
                                                                     self.get_parameter("adjust_filename"))
                        else:
                            # we're generating a service executable
                            working_path = (
                                pathlib.PurePath(agent_build_path.name)
                                / "Service"
                                / "WindowsService1"
                                / "Resources"
                                / "loader.bin"
                            )
                            shutil.move(shellcode_path, working_path)
                            if self.get_parameter('debug'):
                                command = f"dotnet build -c {compileType} -p:OutputType=WinExe -p:Platform=\"Any CPU\""
                            else:
                                command = f"dotnet build -c {compileType} -p:DebugType=None -p:DebugSymbols=false -p:DefineConstants=\"\" -p:OutputType=WinExe -p:Platform=\"Any CPU\""
                            proc = await asyncio.create_subprocess_shell(
                                command,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                                cwd=pathlib.PurePath(agent_build_path.name) / "Service",
                            )
                            stdout, stderr = await proc.communicate()
                            if stdout:
                                stdout_err += f"[stdout]\n{stdout.decode()}"
                            if stderr:
                                stdout_err += f"[stderr]\n{stderr.decode()}"
                            
                            # Check if service build command succeeded
                            if proc.returncode != 0:
                                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                                    PayloadUUID=self.uuid,
                                    StepName="Service Compiling",
                                    StepStdout=f"Service build failed with exit code {proc.returncode}\nCommand: {command}\n{stdout_err}",
                                    StepSuccess=False
                                ))
                                resp.status = BuildStatus.Error
                                resp.payload = b""
                                resp.build_message = f"Service build failed with exit code {proc.returncode}"
                                resp.build_stderr = stdout_err
                                return resp
                            
                            output_path = (
                                pathlib.PurePath(agent_build_path.name)
                                / "Service"
                                / "WindowsService1"
                                / "bin"
                                / f"{buildPath}"
                                / "net451"
                                / "WindowsService1.exe"
                            )
                            output_path = str(output_path)
                            if os.path.exists(output_path):
                                resp.payload = open(output_path, "rb").read()
                                resp.status = BuildStatus.Success
                                resp.build_message = "New Service Executable created!"
                                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                                    PayloadUUID=self.uuid,
                                    StepName="Creating Service",
                                    StepStdout=stdout_err,
                                    StepSuccess=True
                                ))
                                resp.updated_filename = adjust_file_name(self.filename,
                                                                         self.get_parameter("shellcode_format"),
                                                                         self.get_parameter("output_type"),
                                                                         self.get_parameter("adjust_filename"))
                            else:
                                resp.payload = b""
                                resp.status = BuildStatus.Error
                                resp.build_stderr = stdout_err + "\n" + output_path
                                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                                    PayloadUUID=self.uuid,
                                    StepName="Creating Service",
                                    StepStdout=stdout_err,
                                    StepSuccess=False
                                ))

            else:
                # something went wrong, return our errors
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=stdout_err,
                    StepSuccess=False
                ))
                resp.status = BuildStatus.Error
                resp.payload = b""
                resp.build_message = "Unknown error while building payload. Check the stderr for this build."
                resp.build_stderr = stdout_err
        except Exception as e:
            resp.payload = b""
            resp.status = BuildStatus.Error
            resp.build_message = "Error building payload: " + str(traceback.format_exc())
        #await asyncio.sleep(10000)
        return resp

    async def check_if_callbacks_alive(self,
                                       message: PTCheckIfCallbacksAliveMessage) -> PTCheckIfCallbacksAliveMessageResponse:
        response = PTCheckIfCallbacksAliveMessageResponse(Success=True)
        for callback in message.Callbacks:
            if callback.SleepInfo == "":
                continue  # can't do anything if we don't know the expected sleep info of the agent
            try:
                sleep_info = json.loads(callback.SleepInfo)
            except Exception as e:
                continue
            atLeastOneCallbackWithinRange = False
            try:
                for activeC2, info in sleep_info.items():
                    if activeC2 == "websocket" and callback.LastCheckin == "1970-01-01 00:00:00Z":
                        atLeastOneCallbackWithinRange = True
                        continue
                    checkinRangeResponse = await SendMythicRPCCallbackNextCheckinRange(
                        MythicRPCCallbackNextCheckinRangeMessage(
                            LastCheckin=callback.LastCheckin,
                            SleepJitter=info["jitter"],
                            SleepInterval=info["interval"],
                        ))
                    if not checkinRangeResponse.Success:
                        continue
                    lastCheckin = datetime.datetime.strptime(callback.LastCheckin, '%Y-%m-%dT%H:%M:%S.%fZ')
                    minCheckin = datetime.datetime.strptime(checkinRangeResponse.Min, '%Y-%m-%dT%H:%M:%S.%fZ')
                    maxCheckin = datetime.datetime.strptime(checkinRangeResponse.Max, '%Y-%m-%dT%H:%M:%S.%fZ')
                    if minCheckin <= lastCheckin <= maxCheckin:
                        atLeastOneCallbackWithinRange = True
                response.Callbacks.append(PTCallbacksToCheckResponse(
                    ID=callback.ID,
                    Alive=atLeastOneCallbackWithinRange,
                ))
            except Exception as e:
                logger.info(e)
                logger.info(callback.to_json())
        return response


def get_csharp_files(base_path: str) -> list[str]:
    results = []
    for root, dirs, files in os.walk(base_path):
        for name in files:
            if fnmatch.fnmatch(name, "*.cs"):
                results.append(os.path.join(root, name))
    if len(results) == 0:
        raise Exception("No payload files found with extension .cs")
    return results


def filter_config_defines(config_path: str, selected_profiles: list[str]) -> None:
    """
    Modify Config.cs to comment out #define statements for unselected profiles.
    This prevents compilation errors when profile assemblies aren't included.
    """
    profile_defines = {
        'http': '#define HTTP',
        'httpx': '#define HTTPX',
        'smb': '#define SMB',
        'tcp': '#define TCP',
        'websocket': '#define WEBSOCKET'
    }
    
    # Read lines
    with open(config_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Filter lines: comment out unselected profile defines
    filtered_lines = []
    for line in lines:
        modified = False
        for profile_name, define_line in profile_defines.items():
            if define_line in line and profile_name not in selected_profiles:
                # Comment out this define
                filtered_lines.append('//' + line.lstrip())
                modified = True
                break
        
        if not modified:
            filtered_lines.append(line)
    
    # Write back
    with open(config_path, 'w', encoding='utf-8') as f:
        f.writelines(filtered_lines)


def filter_csproj_profile_references(csproj_path: str, selected_profiles: list[str]) -> None:
    """
    Modify Apollo.csproj to include only ProjectReference entries for selected profiles.
    Simple line-by-line filtering
    """
    # Map profile names to their line content in csproj
    profile_lines = {
        'http': '    <ProjectReference Include="..\\HttpProfile\\HttpProfile.csproj" />',
        'httpx': '    <ProjectReference Include="..\\HttpxProfile\\HttpxProfile.csproj" />',
        'smb': '    <ProjectReference Include="..\\NamedPipeProfile\\NamedPipeProfile.csproj" />',
        'tcp': '    <ProjectReference Include="..\\TcpProfile\\TcpProfile.csproj" />',
        'websocket': '    <ProjectReference Include="..\\WebsocketProfile\\WebsocketProfile.csproj" />'
    }
    
    # Also track HttpxTransform
    httpx_transform_line = '    <ProjectReference Include="..\\HttpxTransform\\HttpxTransform.csproj" />'
    
    # Read lines
    with open(csproj_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Filter lines: keep core references and selected profile references
    filtered_lines = []
    for line in lines:
        # Check if this is a profile reference line
        is_profile_line = False
        for profile_name, profile_line in profile_lines.items():
            if profile_line in line:
                # Keep only if this profile is selected
                if profile_name in selected_profiles:
                    filtered_lines.append(line)
                is_profile_line = True
                break
        
        # Check if this is HttpxTransform line
        if httpx_transform_line in line:
            # Keep only if httpx is selected
            if 'httpx' in selected_profiles:
                filtered_lines.append(line)
        elif not is_profile_line:
            # Keep all non-profile lines as-is
            filtered_lines.append(line)
    
    # Write back
    with open(csproj_path, 'w', encoding='utf-8') as f:
        f.writelines(filtered_lines)


def adjust_file_name(filename, shellcode_format, output_type, adjust_filename):
    if not adjust_filename:
        return filename
    filename_pieces = filename.split(".")
    original_filename = ".".join(filename_pieces[:-1])
    if output_type == "WinExe":
        return original_filename + ".exe"
    elif output_type == "Service":
        return original_filename + ".exe"
    elif output_type == "Source":
        return original_filename + ".zip"
    elif shellcode_format == "Binary":
        return original_filename + ".bin"
    elif shellcode_format == "Base64":
        return original_filename + ".txt"
    elif shellcode_format == "C":
        return original_filename + ".c"
    elif shellcode_format == "Ruby":
        return original_filename + ".rb"
    elif shellcode_format == "Python":
        return original_filename + ".py"
    elif shellcode_format == "Powershell":
        return original_filename + ".ps1"
    elif shellcode_format == "C#":
        return original_filename + ".cs"
    elif shellcode_format == "Hex":
        return original_filename + ".txt"
    else:
        return filename
