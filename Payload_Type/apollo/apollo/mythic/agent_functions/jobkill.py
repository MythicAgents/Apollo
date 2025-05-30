from mythic_container.MythicCommandBase import *
from mythic_container.MythicGoRPC import *
import json


class JobkillArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require Job ID to terminate as a command line argument.")


class JobkillCommand(CommandBase):
    cmd = "jobkill"
    needs_admin = False
    help_cmd = "jobkill [jid]"
    description = "Kill a job specified by the job identifier (jid)."
    version = 2
    is_exit = False
    supported_ui_features = ["jobkill", "task:job_kill"]
    author = "@djhohnstein"
    argument_class = JobkillArguments
    attackmapping = []

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        killedTaskResp = await SendMythicRPCTaskSearch(MythicRPCTaskSearchMessage(
            TaskID=taskData.Task.ID,
            SearchAgentTaskID=taskData.args.command_line
        ))
        if killedTaskResp.Success:
            if len(killedTaskResp.Tasks) > 0:
                if killedTaskResp.Tasks[0].CommandName == "rpfwd":
                    try:
                        params = json.loads(killedTaskResp.Tasks[0].Params)
                        rpfwdStopResp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                            TaskID=taskData.Task.ID,
                            PortType="rpfwd",
                            Port=params["port"],
                            Username=params["username"] if "username" in params else "",
                            Password=params["password"] if "password" in params else "",
                        ))
                        if rpfwdStopResp.Success:
                            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                TaskID=taskData.Task.ID,
                                Response=f"Stopped Mythic's rpfwd components\n".encode()
                            ))
                        else:
                            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                TaskID=taskData.Task.ID,
                                Response=f"Failed to stop Mythic's rpfwd components: {rpfwdStopResp.Error}\n".encode()
                            ))
                    except Exception as e:
                        logger.error(f"failed to parse rpfwd params as json: {killedTaskResp.Tasks[0].Params}")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp