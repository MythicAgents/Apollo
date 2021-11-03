from mythic_payloadtype_container.MythicCommandBase import *
import json


class RegWriteValueArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "hive": CommandParameter(name="hive",
                                     type=ParameterType.ChooseOne,
                                        description="The hive to query",
                                        required=True,
                                        default_value="HKLM",
                                        choices=["HKLM", "HKCU", "HKU", "HKCR", "HKCC"]),
            "key": CommandParameter(name="Registry Key", required=True, type=ParameterType.String, description='Registry key to interrogate.', default_value='\\'),
            "value_name": CommandParameter(name="Name", required=False, type=ParameterType.String, description='Registry value to write to.', default_value=''),
            "value_value": CommandParameter(name="Value", required=False, type=ParameterType.String, description='New value to store in the above registry value.', default_value=''),
        }

    def split_commandline(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
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
            cmds = self.split_commandline()
            if len(cmds) != 3:
                raise Exception("Failed to parse command line arguments. Expected two arguments, got {}\n\tUsage: {}".format(cmds, RegWriteValueBase.help_cmd))
            
            parts = cmds[0].split("\\")
            hiveMap = {
                "HKEY_LOCAL_MACHINE": "HKLM",
                "HKEY_CURRENT_USER": "HKCU",
                "HKEY_USERS": "HKU",
                "HKEY_CLASSES_ROOT": "HKCR",
                "HKEY_CURRENT_CONFIG": "HKCC"
            }
            hiveClean = parts[0].replace(":", "").strip().upper()
            if hiveClean in hiveMap.keys():
                self.add_arg("hive", hiveMap[hiveClean])
            elif hiveClean in ["HKLM", "HKCU", "HKU", "HKCR", "HKCC"]:
                self.add_arg("hive", hiveClean)
            else:
                raise Exception("Invalid hive: " + hiveClean)
            self.add_arg("key", "\\".join(parts[1:]))
            self.add_arg("value_name", cmds[1])
            self.add_arg("value_value", cmds[2])
        pass


class RegWriteValueBase(CommandBase):
    cmd = "reg_write_value"
    needs_admin = False
    help_cmd = "reg_write_value [key] [value_name] [new_value]"
    description = "Write a new value to the [value_name] value under the specified registry key [key].\n\nEx: reg_write_value HKLM:\\ '' 1234"
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = RegWriteValueArguments
    attackmapping = ["T1547", "T1037", "T1546", "T1574", "T1112", "T1003"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        key = task.args.get_arg("key")
        if key[0] == "\\":
            task.display_params = "{}:{} '{}' '{}'".format(task.args.get_arg("hive"), key, task.args.get_arg("value_name"), task.args.get_arg("value_value"))
        else:
            task.display_params = "{}:\\{} '{}' '{}'".format(task.args.get_arg("hive"), key, task.args.get_arg("value_name"), task.args.get_arg("value_value"))
        return task

    async def process_response(self, response: AgentResponse):
        pass