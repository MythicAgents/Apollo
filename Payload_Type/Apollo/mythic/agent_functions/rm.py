from CommandBase import *
import json


class RmArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "path": CommandParameter(name="File to Remove", type=ParameterType.String, description="The file to remove on the specified host (if empty, defaults to localhost)", required=True),
            "host": CommandParameter(name="Host", type=ParameterType.String, description="Computer from which to remove the file.", required=False)
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                host = ""
                if self.command_line[0] == "\\" and self.command_line[1] == "\\":
                    final = self.command_line.find("\\", 2)
                    if final != -1:
                        host = self.command_line[2:final]
                self.add_arg("host", host)
                self.add_arg("path", self.command_line)
        else:
            raise Exception("rm requires a path to remove.\n\tUsage: {}".format(RmCommand.help_cmd))
        path = self.get_arg("path")
        if path != "" and path != None:
            path = path.strip()
            if path[0] == '"' and path[-1] == '"':
                path = path[1:-1]
            elif path[0] == "'" and path[-1] == "'":
                path = path[1:-1]
            self.add_arg("path", path)


class RmCommand(CommandBase):
    cmd = "rm"
    needs_admin = False
    help_cmd = "rm [path]"
    description = "Delete a file specified by [path]"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = True
    author = "@djhohnstein"
    argument_class = RmArguments
    attackmapping = ["T1106", "T1107"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass