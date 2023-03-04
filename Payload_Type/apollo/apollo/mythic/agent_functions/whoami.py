from mythic_container.MythicCommandBase import *
import json


class WhoamiArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("whoami takes no command line arguments.")
        pass


class WhoamiCommand(CommandBase):
    cmd = "whoami"
    needs_admin = False
    help_cmd = "whoami"
    description = "Get the username associated with your current thread token."
    version = 2
    author = "@djhohnstein"
    argument_class = WhoamiArguments
    attackmapping = ["T1033"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass