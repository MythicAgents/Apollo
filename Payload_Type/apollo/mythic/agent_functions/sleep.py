from mythic_payloadtype_container.MythicCommandBase import *
import json


class SleepArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("sleep requires an integer value (in seconds) to be passed on the command line to update the sleep value to.")
        parts = self.command_line.split(" ", maxsplit=1)
        try:
            int(parts[0])
        except:
            raise Exception("sleep requires an integer value (in seconds) to be passed on the command line to update the sleep value to.")
        if len(parts) == 2:
            try:
                int(parts[1])
            except:
                raise Exception("sleep requires an integer value for jitter, but received: {}".format(parts[1]))
        pass


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep [seconds] [jitter]"
    description = "Change the implant's sleep interval."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = SleepArguments
    attackmapping = ["T1029"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass