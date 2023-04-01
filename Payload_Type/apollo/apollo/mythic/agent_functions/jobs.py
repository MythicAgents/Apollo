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

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        result = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

        resp = response["jobs"]
        jobs = []
        for job in resp:
            job_resp = await MythicRPC().execute("get_task_for_id",
                                              task_id=task.Task.ID,
                                              requested_uuid=job)
            if job_resp.status == MythicStatus.Success:
                jobs.append(job_resp.response)
            else:
                raise Exception("Failed to get job info for job {}".format(job))
            
        addoutput_resp = await MythicRPC().execute("create_output",
                                                task_id=task.Task.ID,
                                                output=json.dumps(jobs))
        if addoutput_resp.status != MythicStatus.Success:
            raise Exception("Failed to add output to task")
        return result
        