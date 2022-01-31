from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *

class SocksArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port", 
                cli_name="Port",
                display_name="Port",
                type=ParameterType.Number,
                description="Port to start the socks server on."),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must be passed a port on the command line.")
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            port = self.command_line.lower().strip()
            try:
                self.add_arg("port", int(port))
            except Exception as e:
                raise Exception("Invalid port number given: {}. Must be int.".format(port))


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks [port number]"
    description = "Enable SOCKS 5 compliant proxy to send data to the target network. Compatible with proxychains and proxychains4."
    version = 2
    script_only = True
    author = "@djhohnstein"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes=CommandAttributes(
        dependencies=[]
    )
    async def create_tasking(self, task: MythicTask) -> MythicTask:

        resp = await MythicRPC().execute("control_socks",
                                         task_id=task.id,
                                         start=True,
                                         port=task.args.get_arg("port"))

        
        if resp.status != MythicStatus.Success:
            task.status = MythicStatus.Error
            task.stderr = resp.error
            await MythicRPC().execute("create_output",
                    task_id=task.id,
                    output=resp.error)
        else:
            task.display_params = "Started SOCKS5 server on port {}".format(task.args.get_arg("port"))
            task.status = MythicStatus.Success
        return task


    async def process_response(self, response: AgentResponse):
        pass

