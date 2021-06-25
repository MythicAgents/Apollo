from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
from time import sleep

class PortFwdArguments(TaskArguments):

    valid_actions = ["start", "stop","list", "flush"]

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "action": CommandParameter(name="action", choices=["start","stop","list","flush"], required=True, type=ParameterType.ChooseOne, description="Start,stop or list the port forward."),
            "port": CommandParameter(name="Local Port", required=False, type=ParameterType.Number, description="Port to listen on C2."),
            "rport": CommandParameter(name="Remote Port", required=False, type=ParameterType.Number, description="Port to be forwarded."),
            "rip": CommandParameter(name="Remote Ip", required=False, type=ParameterType.String, description="IP to be forwarded."),
        }

    async def parse_arguments(self):
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            parts = self.command_line.lower().split()
            action = parts[0]
            if action not in self.valid_actions:
                raise Exception("Invalid action specfiied. Got {}, but must be one of {}".format(action, ", ".join(self.valid_actions)))
            if action not in self.valid_actions:
                raise Exception("Invalid action \"{}\" given. Require one of: {}".format(action, ", ".join(self.valid_actions)))
            self.add_arg("action", action)
            if action == "start":
                if len(parts) != 4:
                    raise Exception("Invalid command line given for 'rportfwd start'. Must be of the form 'start [local_port] [remote_port] [remote_ip]")
                port = parts[1]
                rport = parts[2]
                rip = parts[3]
                try:
                    self.add_arg("port", int(port))
                except:
                    raise Exception("Invalid port number specified. Expected int, but got: {}".format(port))
                try:
                    self.add_arg("rport", int(rport))
                except:
                    raise Exception("Invalid remote port number specified. Expected int, but got: {}".format(rport))
                
                self.add_arg("rip", rip)
            if action == "stop":
                if len(parts) != 2:
                    raise Exception("Invalid command line for 'rportfwd stop'. Must be of the form 'stop [local_port]'")
                try:
                    self.add_arg("port", int(parts[1]))
                except:
                    raise Exception("Invalid port number specified. Expected int, but got: {}".format(parts[1]))


class PortFwdCommand(CommandBase):
    cmd = "rportfwd"
    needs_admin = False
    help_cmd = "rportfwd [action] [local port] [remote port] [remote IP]"
    description = "Forwards the traffic to the selected port and IP through the local Port."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@tmayllart"
    argument_class = PortFwdArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        resp = ""
        action = task.args.get_arg("action")
        local_port = task.args.get_arg("port")
        remote_port = task.args.get_arg("rport")
        remote_ip = task.args.get_arg("rip")
        display_str = ""
        if action == "start":
            resp = await MythicRPC().execute("control_rportfwd",task_id=task.id,start=True,port=local_port,rport=remote_port,rip=remote_ip)
            if resp.status != MythicStatus.Success:
                raise Exception("Failed to start rportfwd server on {}: {}".format(local_port, resp.error))
            display_str = "{} {} {} {}".format(action, local_port, remote_port, remote_ip)
        elif action == "stop":
            resp = await MythicRPC().execute("control_rportfwd",task_id=task.id,stop=True,port=local_port,rport=remote_port,rip=remote_ip)
            if resp.status != MythicStatus.Success:
                #try again
                sleep(1)
                resp = await MythicRPC().execute("control_rportfwd", task_id=task.id, stop=True, port=local_port,rport=remote_port, rip=remote_ip)
                if resp.status != MythicStatus.Success:
                    raise Exception("Failed to stop port forwarding service on port {}: {}".format(local_port, resp.error))
            display_str = "{} {}".format(action, local_port)
        elif action == "list":
            display_str = "{}".format(action)
        elif action == "flush":
            resp = await MythicRPC().execute("control_rportfwd",task_id=task.id,flush=True,port=local_port,rport=remote_port,rip=remote_ip)
            if resp.status != MythicStatus.Success:
                #try again
                sleep(1)
                resp = await MythicRPC().execute("control_rportfwd", task_id=task.id, flush=True,port=local_port, rport=remote_port,rip=remote_ip)
                if resp.status != MythicStatus.Success:
                    raise Exception("Failed to flush port forwarding service on port {}: {}".format(local_port, resp.error))
            display_str = "{}".format(action)
        else:
            raise Exception("Unexpected code path. Action must be one of start, stop, list, or flush, but got: {}".format(action))
        task.display_params = display_str
        return task

    async def process_response(self, response: AgentResponse):
        pass
