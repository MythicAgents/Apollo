from mythic_payloadtype_container.MythicCommandBase import *
import json


class IfconfigArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("ifconfig takes no command line arguments.")
        pass


class IfconfigCommand(CommandBase):
    cmd = "ifconfig"
    needs_admin = False
    help_cmd = "ifconfig"
    description = "Get interface information associated with the target."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@thespicybyte"
    argument_class = IfconfigArguments
    attackmapping = ["T1590.005"]
    browser_script = BrowserScript(script_name="ifconfig", author="@thespicybyte", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
