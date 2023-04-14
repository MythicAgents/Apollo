from mythic_container.MythicCommandBase import *
import json


class MakeTokenArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON)
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token (modal popup)"
    description = "Creates a new logon session and applies it to the agent. Modal popup for options. Credentials must be populated in the credential store."
    version = 2
    author = "@djhohnstein"
    argument_class = MakeTokenArguments
    attackmapping = ["T1134"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        cred = taskData.args.get_arg("credential")
        response.DisplayParams = "{}\\{} {}".format(cred.get("realm"), cred.get("account"), cred.get("credential"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp