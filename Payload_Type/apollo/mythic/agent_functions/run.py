from mythic_payloadtype_container.MythicCommandBase import *
import json


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
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the executable.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    )
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("run requires a path to an executable to run.\n\tUsage: {}".format(RunCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", 1)
            self.add_arg("executable", parts[0])
            if len(parts) > 1:
                self.add_arg("arguments", parts[1])
        pass


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run [binary] [arguments]"
    description = "Execute a binary on the target system. This will properly use %PATH% without needing to specify full locations."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = RunArguments
    attackmapping = ["T1106", "T1218", "T1553"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "-Executable {} -Arguments {}".format(
            task.args.get_arg("executable"),
            task.args.get_arg("arguments")
        )
        return task

    async def process_response(self, response: AgentResponse):
        pass