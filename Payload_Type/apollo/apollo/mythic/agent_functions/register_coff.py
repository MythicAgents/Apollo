from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
from apollo.mythic.agent_functions.register_file import *
import base64

class RegisterCoffAlias(RegisterFileCommand, CommandBase):
    cmd = "register_coff"
    attributes=CommandAttributes(
        dependencies=["register_file"],
        alias=True
    )
    needs_admin = False
    help_cmd = "register_coff (modal popup)"
    description = "Import a new COFF into the agent cache."
    version = 2
    author = "@__Retrospect"

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:

        response = await super().create_go_tasking(taskData)
        response.CommandName = super().cmd

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
