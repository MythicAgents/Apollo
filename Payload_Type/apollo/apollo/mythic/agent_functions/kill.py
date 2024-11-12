from mythic_container.MythicCommandBase import *
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
            supplied_dict = json.loads(self.command_line)
            if "pid" in supplied_dict:
                self.add_arg("pid", supplied_dict["pid"])
            elif "process_id" in supplied_dict:
                self.add_arg("pid", supplied_dict["process_id"])
            else:
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
    author = "@djhohnstein"
    argument_class = KillArguments
    attackmapping = ["T1106"]
    supported_ui_features = ["kill", "process_browser:kill"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-PID {}".format(taskData.args.get_arg("pid"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp