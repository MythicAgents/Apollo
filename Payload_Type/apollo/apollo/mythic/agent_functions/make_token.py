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
                type=ParameterType.Credential_JSON,
                limit_credentials_by_type=["plaintext"],
                parameter_group_info=[ParameterGroupInfo(
                    group_name="credential_store",
                    required=True,
                    ui_position=1
                )]
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=1
                )]
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=2
                )]
            ),
            CommandParameter(
                name="netOnly",
                cli_name="netOnly",
                display_name="NetOnly Logon",
                description="NetOnly logons use the LOGON32_LOGON_NEW_CREDENTIALS API, otherwise LOGON32_LOGON_INTERACTIVE is used. NetOnly logons do not use make_token credentials locally, only remotely. Using Interactive logons means that the credentials are used locally as well.",
                default_value=True,
                type=ParameterType.Boolean,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="credential_store",
                        required=False,
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        ui_position=3,
                        required=False,
                    )
                ]
            )
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token -username domain\\user -password abc123"
    description = "Creates a new logon session and applies it to the agent. Modal popup for options and selecting an existing credential."
    version = 2
    author = "@djhohnstein"
    argument_class = MakeTokenArguments
    attackmapping = ["T1134"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        if taskData.args.get_parameter_group_name() == "credential_store":
            cred = taskData.args.get_arg("credential")
            response.DisplayParams = "{}\\{} {}".format(cred.get("realm"), cred.get("account"), cred.get("credential"))
        else:
            username = taskData.args.get_arg("username")
            password = taskData.args.get_arg("password")
            taskData.args.remove_arg("username")
            taskData.args.remove_arg("password")
            usernamePieces = username.split("\\")
            if len(usernamePieces) != 2:
                usernamePieces = [taskData.Callback.Host, usernamePieces[0]]
            cred = {
                "type": "plaintext",
                "realm": usernamePieces[0],
                "credential": password,
                "account": usernamePieces[1]
            }
            taskData.args.add_arg("credential", cred, type=ParameterType.Credential_JSON)
            response.DisplayParams = "{}\\{} {} ({})".format(cred.get("realm"), cred.get("account"), cred.get("credential"),
                                                             "netOnly" if taskData.args.get_arg("netOnly") else "interactive")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp