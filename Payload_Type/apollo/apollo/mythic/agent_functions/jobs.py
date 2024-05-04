from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class JobsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("Jobs takes no arguments.")
        pass


class JobsCommand(CommandBase):
    cmd = "jobs"
    needs_admin = False
    help_cmd = "jobs"
    description = 'List currently executing jobs, excluding the "jobs" and "jobkill" commands.'
    version = 2
    author = "@djhohnstein"
    argument_class = JobsArguments
    attackmapping = []
    browser_script = BrowserScript(script_name="jobs_new", author="@djhohnstein", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        result = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

        resp = response["jobs"]
        jobs = []
        for job in resp:
            job_resp = await SendMythicRPCTaskSearch(MythicRPCTaskSearchMessage(
                TaskID=task.Task.ID,
                SearchAgentTaskID=job
            ))
            if job_resp.Success:
                jobs.append({
                 "agent_task_id": job_resp.Tasks[0].AgentTaskID,
                 "command": job_resp.Tasks[0].CommandName,
                 "display_params": job_resp.Tasks[0].DisplayParams,
                  "operator": job_resp.Tasks[0].OperatorUsername,
                  "display_id": job_resp.Tasks[0].DisplayID})
            else:
                raise Exception("Failed to get job info for job {}".format(job))
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=json.dumps(jobs).encode()
        ))
        return result
        