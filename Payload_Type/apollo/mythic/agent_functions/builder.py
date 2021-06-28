from mythic_payloadtype_container.PayloadBuilder import *
from mythic_payloadtype_container.MythicCommandBase import *
import os, fnmatch, tempfile, sys, asyncio
from distutils.dir_util import copy_tree
import traceback


class Apollo(PayloadType):
    name = "apollo"
    file_extension = "exe"
    author = "@djhohnstein"
    mythic_encrypts = True
    supported_os = [
        SupportedOS.Windows
    ]
    version = "1.1.2"
    wrapper = False
    wrapped_payloads = ["service_wrapper"]
    note = """
A fully featured .NET 4.0 compatible training agent.

Version: {}
    """.format(version)
    supports_dynamic_loading = True
    build_parameters = {
        "version": BuildParameter(name="version", parameter_type=BuildParameterType.ChooseOne, description="Choose a target .NET Framework", choices=["4.0"]),
        "arch": BuildParameter(name="arch", parameter_type=BuildParameterType.ChooseOne, choices=["x64", "x86", "Any CPU"], default_value="any", description="Target architecture"),
        "output_type": BuildParameter(name="output_type", parameter_type=BuildParameterType.ChooseOne, choices=[ "WinExe", "Shellcode", "DLL"], default_value="WinExe", description="Output as shellcode, executable, or dynamically loaded library."),
        "configuration": BuildParameter(name="configuration", parameter_type=BuildParameterType.ChooseOne, choices=["Release"], default_value="Release", description="Build a payload with or without debugging symbols.")
    }
    c2_profiles = ["http", "SMBServer"]
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
        defines_commands_upper = [f"#define {x.upper()}" for x in self.commands.get_commands()]
        special_files_map = {
            "DefaultProfile.cs": {
                "callback_interval": "",
                "callback_jitter": "",
                "callback_port": "",
                "callback_host": "",
                "domain_front": "",
                "encrypted_exchange_check": "",
                "UUID_HERE": self.uuid,
                "AESPSK": "",
            },
            "SMBServerProfile.cs": {
                "pipe_name": "",
                "UUID_HERE": self.uuid,
                "AESPSK": "",
            },
            "Agent.cs": {
                "UUID_HERE": self.uuid
            }
        }
        success_message = f"Apollo {self.uuid} Successfully Built"
        defines_profiles_upper = []
        for c2 in self.c2info:
            profile = c2.get_c2profile()
            defines_profiles_upper.append(f"#define {profile['name'].upper()}")
            if profile["name"] == "http":
                for key, val in c2.get_parameters_dict().items():
                    if isinstance(val, dict):
                        special_files_map["DefaultProfile.cs"][key] = val["enc_key"] if val["enc_key"] is not None else ""
                    elif not isinstance(val, str):
                        special_files_map["DefaultProfile.cs"][key] = json.dumps(val)
                    else:
                        special_files_map["DefaultProfile.cs"][key] = val
            elif profile["name"] == "SMBServer":
                for key, val in c2.get_parameters_dict().items():
                    special_files_map["SMBServerProfile.cs"][key] = val
            elif profile["name"] == "SMBClient":
                pass
            else:
                raise Exception("Unsupported C2 profile type for Apollo: {}".format(profile["name"]))
        # create the payload
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
                for profileFile in special_files_map.keys():
                    if csFile.endswith(profileFile):
                        for key, val in special_files_map[profileFile].items():
                            templateFile = templateFile.replace(key, val)
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
            command = "nuget restore ; msbuild -p:TargetFrameworkVersion=v{} -p:OutputType=\"{}\" -p:Configuration=\"{}\" -p:Platform=\"{}\"".format(
                self.get_parameter('version'),
                outputType,
                self.get_parameter('configuration'),
                self.get_parameter('arch'))
            proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
            stdout, stderr = await proc.communicate()
            stdout_err = ""
            if stdout:
                stdout_err += f'[stdout]\n{stdout.decode()}\n'
            if stderr:
                stdout_err += f'[stderr]\n{stderr.decode()}' + "\n" + command
            if self.get_parameter('arch') == "Any CPU":
                output_path = "{}/Apollo/bin/{}/Apollo.{}".format(agent_build_path.name, self.get_parameter('configuration'), file_ext)
            else:
                output_path = "{}/Apollo/bin/{}/{}/Apollo.{}".format(agent_build_path.name, self.get_parameter('arch'), self.get_parameter('configuration'), file_ext)
            if os.path.exists(output_path):
                resp.status = BuildStatus.Success
                if self.get_parameter('output_type') != "Shellcode":
                    resp.payload = open(output_path, 'rb').read()
                    resp.message = success_message
                else:
                    command = "chmod 777 {}/donut; chmod +x {}/donut".format(agent_build_path.name, agent_build_path.name)
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr= asyncio.subprocess.PIPE, cwd=agent_build_path.name)
                    stdout, stderr = await proc.communicate()
                    stdout_err += "Changing donut to be executable..."
                    stdout_err += stdout.decode()
                    stdout_err += stderr.decode()
                    stdout_err += "Done."

                    # need to go through one more step to turn our exe into shellcode
                    if self.get_parameter('arch') == "x64" or self.get_parameter('arch') == "Any CPU":
                        command = "{}/donut -f 1 -a 2 {}".format(agent_build_path.name, output_path)
                    else:
                        command = "{}/donut -f 1 -a 1 {}".format(agent_build_path.name, output_path)
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
                    stdout, stderr = await proc.communicate()
                    if stdout:
                        stdout_err += f'[stdout]\n{stdout.decode()}'
                    if stderr:
                        stdout_err += f'[stderr]\n{stderr.decode()}'
                    if os.path.exists("{}/loader.bin".format(agent_build_path.name)):
                        resp.payload = open("{}/loader.bin".format(agent_build_path.name), 'rb').read()
                        resp.status = BuildStatus.Success
                        resp.build_message = success_message
                        resp.build_stdout = stdout_err
                    else:
                        resp.status = BuildStatus.Error
                        resp.build_message = stdout_err
                        resp.build_stdout = stdout_err
                        resp.payload = b""
            else:
                # something went wrong, return our errors
                resp.status = BuildStatus.Error
                resp.payload = b""
                resp.build_message = stdout_err
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
