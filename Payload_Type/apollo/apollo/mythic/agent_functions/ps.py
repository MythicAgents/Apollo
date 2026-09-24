from mythic_container.MythicCommandBase import *
import json


class PsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="extended",
                type=ParameterType.Boolean,
                default_value=False,
                description="Include parent PID, command line, window title, and executable file metadata.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=1, group_name="Default")
                ],
            )
        ]

    async def parse_arguments(self):
        command = self.command_line.strip()
        if command.startswith("{"):
            self.load_args_from_json_string(command)
        elif command == "--extended":
            self.add_arg("extended", True, ParameterType.Boolean)
        elif command:
            raise Exception("Usage: ps [--extended]")


class PsCommand(CommandBase):
    cmd = "ps"
    needs_admin = False
    help_cmd = "ps [--extended]"
    description = "List processes with limited query access; --extended adds slower process details."
    version = 4
    supported_ui_features = ["process_browser:list"]
    author = "@djhohnstein"
    argument_class = PsArguments
    attackmapping = ["T1106"]
    browser_script = BrowserScript(script_name="ps_new", author="@djhohnstein")
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
