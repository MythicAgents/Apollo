from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64
import sys
from apollo.mythic.agent_functions.register_file import *

class RegisterAssemblyAlias(RegisterFileCommand, CommandBase):
    cmd = "register_assembly"
    attributes=CommandAttributes(
        dependencies=["register_file"],
        alias=True
    )
    needs_admin = False
    help_cmd = "register_assembly (modal popup)"
    description = "Import a new Assembly into the agent cache."
    version = 2
    author = "@djhohnstein"


    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:

        response = await super().create_go_tasking(taskData)
        response.CommandName = super().cmd

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
