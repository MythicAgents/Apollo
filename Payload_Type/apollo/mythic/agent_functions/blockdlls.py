from mythic_payloadtype_container.MythicCommandBase import *
import json


class BlockDllsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="block",
                cli_name="EnableBlock",
                display_name="Block Non-Microsoft DLLs",
                type=ParameterType.Boolean,
                default_value=True,
                description="Block non-Microsoft DLLs from being loaded.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=1,
                        group_name="Default",
                    )
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No action given.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            cmd = self.command_line.strip().lower()
            if cmd == "true" or cmd == "on":
                self.add_arg("block", True, ParameterType.Boolean)
            elif cmd == "false" or cmd == "off":
                self.add_arg("block", False, ParameterType.Boolean)
            else:
                raise Exception("Invalid command line arguments for blockdlls.")
            

class BlockDllsCommand(CommandBase):
    cmd = "blockdlls"
    needs_admin = False
    help_cmd = "blockdlls [on|off]"
    description = "Block non-Microsoft DLLs from loading into sacrificial processes."
    version = 3
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = BlockDllsArguments
    attackmapping = ["T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        block = task.args.get_arg("block")
        if block:
            task.display_params = "on"
        else:
            task.display_params = "off"
        return task

    async def process_response(self, response: AgentResponse):
        pass