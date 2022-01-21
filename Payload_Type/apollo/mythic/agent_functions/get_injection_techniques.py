from mythic_payloadtype_container.MythicCommandBase import *
import json


class GetInjectionTechniquesArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

class GetInjectionTechniquesCommand(CommandBase):
    cmd = "get_injection_techniques"
    needs_admin = False
    help_cmd = "get_injection_techniques"
    description = "List the currently available injection techniques the agent knows about."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = GetInjectionTechniquesArguments
    attackmapping = []
    browser_script = BrowserScript(script_name="get_injection_techniques", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass