from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
import base64


class ShInjectArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number),
            "shellcode": CommandParameter(name="Shellcode File", type=ParameterType.File)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(ShInjectCommand.help_cmd))
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(ShInjectCommand.help_cmd))
        self.load_args_from_json_string(self.command_line)
        pass


class ShInjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject (modal popup)"
    description = "Inject shellcode into a remote process."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ShInjectArguments
    attackmapping = ["T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        original_file_name = json.loads(task.original_params)['Shellcode File']
        resp = await MythicRPC().execute("create_file",
                                         task_id=task.id,
                                         file=base64.b64encode(task.args.get_arg("shellcode")).decode(),
                                         delete_after_fetch=False)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("shellcode", resp.response['agent_file_id'])
        else:
            raise Exception(f"Failed to host sRDI loader stub: {resp.error}")
        task.display_params = "{} into PID {}".format(original_file_name, task.args.get_arg("pid"))
        return task

    async def process_response(self, response: AgentResponse):
        pass
