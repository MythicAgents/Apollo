from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

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
    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
            TaskID=taskData.Task.ID,
            PortType="socks",
            LocalPort=taskData.args.get_arg("port")
        ))

        if not resp.Success:
            response.TaskStatus = MythicStatus.Error
            response.Stderr = resp.Error
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=resp.Error.encode()
            ))
        else:
            response.DisplayParams = "Started SOCKS5 server on port {}".format(taskData.args.get_arg("port"))
            response.TaskStatus = MythicStatus.Success
            response.Completed = True
        return response


    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

