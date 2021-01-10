from CommandBase import *
import json
from MythicPortFwdRPC import *

class PortFwdArguments(TaskArguments):

    valid_actions = ["start", "stop","list"]

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "action": CommandParameter(name="action", choices=["start","stop","list","flush"], required=True, type=ParameterType.ChooseOne, description="Start,stop or list the port forward."),
            "port": CommandParameter(name="Local Port", required=False, type=ParameterType.Number, description="Port to listen on C2."),
            "rport": CommandParameter(name="Remote Port", required=False, type=ParameterType.Number, description="Port to be forwarded."),
            "rip": CommandParameter(name="Remote Ip", required=False, type=ParameterType.String, description="IP to be forwarded."),
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must be passed \"start\",\"stop\",\"list\" or \"flush\" commands on the command line.")
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            parts = self.command_line.lower().split()
            action = parts[0]
            port = parts[1]
            rport = parts[2]
            rip = parts[3]
            if action not in self.valid_actions:
                raise Exception("Invalid action \"{}\" given. Require one of: {}".format(action, ", ".join(self.valid_actions)))
            self.add_arg("action", action)
            if action == "start":
                if port == "":
                    raise Exception("Invalid Port number given: {}. Must be int.".format(parts[1]))
                if rport == "":
                    raise Exception("Invalid Remot Port number given: {}. Must be int.".format(parts[1]))
                if rip == "":
                    raise Exception("Invalid Remot IP given: {}. Must be int.".format(parts[1]))
            if action == "stop":
                if port == "":
                    raise Exception("Invalid Port number given: {}. Must be int.".format(parts[1]))


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
        if task.args.get_arg("action") == "start":
            resp = await MythicPortFwdRPC(task).start_rportfwd(task.args.get_arg("port"),task.args.get_arg("rport"),task.args.get_arg("rip"))
        if task.args.get_arg("action") == "stop":
            resp = await MythicPortFwdRPC(task).stop_rportfwd(task.args.get_arg("port"))
        if task.args.get_arg("action") == "list":
            return task
        if task.args.get_arg("action") == "flush":
            resp = await MythicPortFwdRPC(task).flush_rportfwd()
        if resp.status == MythicStatus.Success:
            return task
        else:
            task.status = MythicStatus.Error
        return task

    async def process_response(self, response: AgentResponse):
        pass
