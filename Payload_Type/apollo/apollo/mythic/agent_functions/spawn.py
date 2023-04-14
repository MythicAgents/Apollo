from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from mythic_container.MythicRPC import *
import asyncio

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
    author = "@djhohnstein"
    argument_class = SpawnArguments
    attackmapping = ["T1055"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        payload_search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
            CallbackID=taskData.Callback.ID,
            PayloadUUID=taskData.args.get_arg("template")))
        newPayloadResp = await SendMythicRPCPayloadCreateFromUUID(MythicRPCPayloadCreateFromUUIDMessage(
            TaskID=taskData.Task.ID, PayloadUUID=taskData.args.get_arg("template"), NewDescription="{}'s spawned session from task {}".format(taskData.Task.OperatorUsername, str(taskData.Task.DisplayID)))
        )
        if newPayloadResp.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
                    PayloadUUID=newPayloadResp.NewPayloadUUID
                ))
                if resp.Success:
                    if resp.Payloads[0].BuildPhase == 'success':
                        taskData.args.add_arg("template", resp.Payloads[0].AgentFileId)
                        response.DisplayParams = "Spawning new payload from '{}'".format(payload_search.Payloads[0].Description)
                        break
                    elif resp.Payloads[0].BuildPhase == 'error':
                        raise Exception("Failed to build new payload")
                    elif resp.Payloads[0].BuildPhase == "building":
                        await asyncio.sleep(2)
                    else:
                        raise Exception(resp.Payloads[0].BuildPhase)
                else:
                    raise Exception(resp.Error)
        else:
            raise Exception("Failed to start build process")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
