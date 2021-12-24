from mythic_payloadtype_container.MythicCommandBase import *
import json


class LinkArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connection_info",
                cli_name="NewConnection",
                type=ParameterType.ConnectionInfo)
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Link command requires arguments, but got empty command line.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob of arguments, but got raw command line.")
        self.load_args_from_json_string(self.command_line)

class LinkCommand(CommandBase):
    cmd = "link"
    needs_admin = False
    help_cmd = "link"
    description = "Link to a new agent on a remote host or re-link back to a specified callback that's been unlinked via the `unlink` commmand."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = LinkArguments
    attackmapping = ["T1570", "T1572", "T1021"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "{}".format(task.args.get_arg("connection_info")["host"])
        return task

    async def process_response(self, response: AgentResponse):
        pass