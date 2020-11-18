from CommandBase import *
import json
from MythicFileRPC import *


class MeterpreterArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number),
            "payload_type": CommandParameter(name="Payload Type", type=ParameterType.String),
            "lhost": CommandParameter(name="LHOST", type=ParameterType.String),
            "lport": CommandParameter(name="LPORT", type=ParameterType.Number)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(MeterpreterCommand.help_cmd))
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(MeterpreterCommand.help_cmd))
        self.load_args_from_json_string(self.command_line)
        pass


class MeterpreterCommand(CommandBase):
    cmd = "meterpreter"
    needs_admin = False
    help_cmd = "meterpreter (modal popup)"
    description = "Inject a meterpreter reverse stager into a remote process."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@reznok"
    argument_class = MeterpreterArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass