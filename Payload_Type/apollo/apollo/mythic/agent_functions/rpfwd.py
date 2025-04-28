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
                description="Port to listen for connections on the target host.",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=1,
                )]
            ),
            CommandParameter(
                name="remote_port",
                cli_name="RemotePort",
                display_name="Remote Port",
                type=ParameterType.Number,
                description="Remote port to send rpfwd traffic to.",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=3,
                )]
            ),
            CommandParameter(
                name="remote_ip",
                cli_name="RemoteIP",
                display_name="Remote IP",
                type=ParameterType.String,
                description="Remote IP to send rpfwd traffic to.",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=2,
                )]
            ),
            CommandParameter(
                name="username",
                cli_name="Username",
                display_name="Port Auth Username",
                type=ParameterType.String,
                description="Must auth as this user to use the SOCKS port.",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    ui_position=4,
                )]
            ),
            CommandParameter(
                name="password",
                cli_name="Password",
                display_name="Port Auth Password",
                type=ParameterType.String,
                description="Must auth with this password to use the SOCKS port.",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    ui_position=5,
                )]
            ),
            CommandParameter(
                name="debugLevel",
                cli_name="DebugLevel",
                display_name="DebugLevel",
                type=ParameterType.ChooseOne,
                choices=["None", "Connections", "Received Data", "Sent Data"],
                default_value="Connections",
                description="Report debug messages back to Mythic. 'Connections' is just data about new/closed connections, 'Received Data' is connections plus data sent to the local port Apollo is bound to, 'Sent Data' is the other two plus data that Apollo is sending back to the remote connection.",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    ui_position=6,
                )]
            ),
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
            RemotePort=taskData.args.get_arg("remote_port"),
            Username=taskData.args.get_arg("username"),
            Password=taskData.args.get_arg("password")
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
            if taskData.args.get_arg("debugLevel") != "None":
                response.DisplayParams += f" with debug level of \"{taskData.args.get_arg('debugLevel')}\""
        debugLevel = taskData.args.get_arg("debugLevel")
        if debugLevel == "None":
            taskData.args.add_arg("debugLevel", value=0, type=ParameterType.Number)
        elif debugLevel == "Connections":
            taskData.args.add_arg("debugLevel", value=1, type=ParameterType.Number)
        elif debugLevel == "Received Data":
            taskData.args.add_arg("debugLevel", value=2, type=ParameterType.Number)
        else:
            taskData.args.add_arg("debugLevel", value=3, type=ParameterType.Number)
        return response


    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

