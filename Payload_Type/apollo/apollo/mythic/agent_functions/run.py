from mythic_container.MythicCommandBase import *
import json


def split_command_line(command_line):
    """Split the executable token from a Windows command line.

    The executable token is kept verbatim, including any surrounding quotes, so
    the agent can pass it directly to CreateProcess as part of the command line.
    Arguments are otherwise left untouched.
    """
    command_line = command_line.lstrip()
    if not command_line:
        raise ValueError("No executable was provided.")

    in_quotes = False
    backslash_count = 0
    for index, character in enumerate(command_line):
        if character == "\\":
            backslash_count += 1
            continue

        if character == '"' and backslash_count % 2 == 0:
            in_quotes = not in_quotes
        elif character.isspace() and not in_quotes:
            arguments = command_line[index:].lstrip()
            return command_line[:index], arguments or None

        backslash_count = 0

    if in_quotes:
        raise ValueError("The executable contains an unmatched quote.")

    return command_line, None


class RunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="executable",
                cli_name="Executable",
                display_name="Executable",
                type=ParameterType.String,
                description="Path to an executable to run.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the executable.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=1)
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception(
                "run requires a path to an executable to run.\n\tUsage: {}".format(
                    RunCommand.help_cmd
                )
            )
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            executable, arguments = split_command_line(self.command_line)
            self.add_arg("executable", executable)
            if arguments is not None:
                self.add_arg("arguments", arguments)
        pass


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run [binary] [arguments]"
    description = "Execute a binary on the target system. This will properly use %PATH% without needing to specify full locations."
    version = 2
    author = "@djhohnstein"
    argument_class = RunArguments
    attackmapping = ["T1106", "T1218", "T1553"]
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-Executable {} -Arguments {}".format(
            taskData.args.get_arg("executable"), taskData.args.get_arg("arguments")
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp