from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from apollo.mythic.sRDI import ShellcodeRDI
from os import path
from mythic_container.MythicRPC import *
import base64
from .execute_pe import *


class PrintSpooferArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            # CommandParameter(
            #     name="command",
            #     cli_name="Command",
            #     display_name="Command(s)",
            #     type=ParameterType.String,
            #     description="PrintSpoofer command to run (can be one or more)."),
        ]

    async def parse_arguments(self):
        if len(self.command_line):
            self.add_arg("command", "printspoofer.exe {}".format(self.command_line))
        else:
            raise Exception("No PrintSpoofer command given to execute.\n\tUsage: {}".format(PrintSpooferCommand.help_cmd))


class PrintSpooferCommand(CommandBase):
    cmd = "printspoofer"
    attributes=CommandAttributes(
        dependencies=["execute_pe"],
        alias=True
    )
    needs_admin = False
    help_cmd = "printspoofer [args]"
    description = "Execute one or more PrintSpoofer commands"
    version = 2
    author = "@djhohnstein"
    argument_class = PrintSpooferArguments
    attackmapping = ["T1547"]
    script_only = False

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        commandline = taskData.args.command_line
        executePEArgs = ExecutePEArguments(command_line=json.dumps(
            {
                "pe_name": "printspoofer.exe",
                "pe_arguments": commandline,
            }
        ))
        await executePEArgs.parse_arguments()
        executePECommand = ExecutePECommand(agent_path=self.agent_code_path,
                                            agent_code_path=self.agent_code_path,
                                            agent_browserscript_path=self.agent_browserscript_path)
        # set our taskData args to be the new ones for execute_pe
        taskData.args = executePEArgs
        # executePE's creat_go_tasking function returns a response for us
        newResp = await executePECommand.create_go_tasking(taskData=taskData)
        # update the response to make sure this gets pulled down as execute_pe instead of mimikatz
        newResp.CommandName = "execute_pe"
        newResp.DisplayParams = commandline
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
