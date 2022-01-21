from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from mythic_payloadtype_container.MythicRPC import *


class SpawnArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="template",
                cli_name="Payload",
                display_name="Payload Template (Shellcode)",
                type=ParameterType.Payload,
                supported_agents=["apollo"],
                supported_agent_build_parameters={"apollo": {"output_type": "Shellcode"}}),
        ]

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
    version = 2
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
        temp = await MythicRPC().execute("get_payload", payload_uuid=task.args.get_arg("template"))
        gen_resp = await MythicRPC().execute("create_payload_from_uuid",
                                             task_id=task.id,
                                             payload_uuid=task.args.get_arg('template'),
                                             new_description="{}'s spawned session from task {}".format(task.operator, str(task.id)))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicRPC().execute("get_payload", payload_uuid=gen_resp.response["uuid"])
                if resp.status == MythicStatus.Success:
                    if resp.response["build_phase"] == 'success':
                        base64contents = resp.response["contents"]
                        pe = base64.b64decode(base64contents)
                        if len(pe) > 1 and pe[:2] == b"\x4d\x5a":
                            raise Exception("spawn requires a payload of Raw output, but got an executable.")
                        # it's done, so we can register a file for it
                        task.args.add_arg("template", resp.response["file"]["agent_file_id"])
                        task.display_params = "Spawning new payload from '{}'".format(temp.response['tag'])
                        break
                    elif resp.response["build_phase"] == 'error':
                        raise Exception("Failed to build new payload: {}".format(resp.response["error_message"]))
                    elif resp.response["build_phase"] == "building":
                        await asyncio.sleep(2)
                    else:
                        raise Exception(resp.response["build_phase"])
                else:
                    raise Exception(resp.response["error_message"])
        else:
            raise Exception("Failed to start build process")



        return task

    async def process_response(self, response: AgentResponse):
        pass
