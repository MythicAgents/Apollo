from mythic_payloadtype_container.MythicCommandBase import *
import json


class RegQueryValuesArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "key": CommandParameter(name="Registry Key", required=True, type=ParameterType.String, description='Registry key to interrogate.', default_value='HKLM:\\'),
        }

    def split_commandline(self):
        if self.command_line[0] == "{":
            raise Exception("split_commandline expected string, but got JSON object: " + self.command_line)
        inQuotes = False
        curCommand = ""
        cmds = []
        for x in range(len(self.command_line)):
            c = self.command_line[x]
            if c == '"' or c == "'":
                inQuotes = not inQuotes
            if (not inQuotes and c == ' '):
                cmds.append(curCommand)
                curCommand = ""
            else:
                curCommand += c
        
        if curCommand != "":
            cmds.append(curCommand)
        
        for x in range(len(cmds)):
            if cmds[x][0] == '"' and cmds[x][-1] == '"':
                cmds[x] = cmds[x][1:-1]
            elif cmds[x][0] == "'" and cmds[x][-1] == "'":
                cmds[x] = cmds[x][1:-1]

        return cmds

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("key", self.command_line)
        pass


class RegQueryValues(CommandBase):
    cmd = "reg_query_values"
    needs_admin = False
    help_cmd = "reg_query_values [key]"
    description = "Query registry values for an associated registry key [key]."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = RegQueryValuesArguments
    attackmapping = ["T1012", "T1552"]
    browser_script = BrowserScript(script_name="reg_query_values", author="@djhohnstein")

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("key")
        return task

    async def process_response(self, response: AgentResponse):
        pass