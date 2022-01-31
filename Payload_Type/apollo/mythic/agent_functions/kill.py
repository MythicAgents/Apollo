from mythic_payloadtype_container.MythicCommandBase import *
import json


class KillArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID",
                type=ParameterType.Number)
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No PID given.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            try:
                int(self.command_line)
            except:
                raise Exception("Failed to parse integer PID from: {}\n\tUsage: {}".format(self.command_line, killCommand.help_cmd))
            self.add_arg("pid", int(self.command_line), ParameterType.Number)
        

class killCommand(CommandBase):
    cmd = "kill"
    needs_admin = False
    help_cmd = "kill [pid]"
    description = "Kill a process specified by [pid]"
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = KillArguments
    attackmapping = ["T1106"]
    supported_ui_features = ["kill"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "-PID {}".format(task.args.get_arg("pid"))
        return task

    async def process_response(self, response: AgentResponse):
        pass