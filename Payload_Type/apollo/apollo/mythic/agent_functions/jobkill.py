from mythic_container.MythicCommandBase import *
import json


class JobkillArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require Job ID to terminate as a command line argument.")


class JobkillCommand(CommandBase):
    cmd = "jobkill"
    needs_admin = False
    help_cmd = "jobkill [jid]"
    description = "Kill a job specified by the job identifier (jid)."
    version = 2
    is_exit = False
    supported_ui_features = ["jobkill"]
    author = "@djhohnstein"
    argument_class = JobkillArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass