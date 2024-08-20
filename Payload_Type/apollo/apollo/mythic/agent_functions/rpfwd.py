from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class RpfwdArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port", 
                cli_name="Port",
                display_name="Port",
                type=ParameterType.Number,
                description="Port to listen for connections on the target host."),
            CommandParameter(
                name="remote_port",
                cli_name="RemotePort",
                display_name="Remote Port",
                type=ParameterType.Number,
                description="Remote port to send rpfwd traffic to."),
            CommandParameter(
                name="remote_ip",
                cli_name="RemoteIP",
                display_name="Remote IP",
                type=ParameterType.String,
                description="Remote IP to send rpfwd traffic to."),
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


class RpfwdCommand(CommandBase):
    cmd = "rpfwd"
    needs_admin = False
    help_cmd = "rpfwd -Port 445 -RemoteIP 1.2.3.4 -RemotePort 80"
    description = "Start listening on a port on the target host and forwarding traffic through Mythic to the remoteIP:remotePort. Stop this with the jobs and jobkill commands"
    version = 2
    script_only = False
    author = "@its_a_feature_"
    argument_class = RpfwdArguments
    attackmapping = []
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
            PortType="rpfwd",
            LocalPort=taskData.args.get_arg("port"),
            RemoteIP=taskData.args.get_arg("remote_ip"),
            RemotePort=taskData.args.get_arg("remote_port")
        ))

        if not resp.Success:
            response.TaskStatus = MythicStatus.Error
            response.Stderr = resp.Error
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=resp.Error.encode()
            ))
            response.Completed = True
            response.TaskStatus = MythicStatus.Success
        else:
            response.DisplayParams = f"on port {taskData.args.get_arg('port')} sending to {taskData.args.get_arg('remote_ip')}:{taskData.args.get_arg('remote_port')}"
        return response


    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

