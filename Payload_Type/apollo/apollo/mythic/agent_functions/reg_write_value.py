from mythic_container.MythicCommandBase import *
import json


class RegWriteValueArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hive",
                cli_name="Hive",
                display_name="Registry Hive",
                type=ParameterType.ChooseOne,
                description="The hive to query",
                default_value="HKLM",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=1
                    ),
                ],
                choices=["HKLM", "HKCU", "HKU", "HKCR", "HKCC"]
            ),
            CommandParameter(
                name="key",
                cli_name="Key",
                display_name="Registry Key",
                type=ParameterType.String,
                description='Registry key to interrogate.',
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2
                    ),
                ],
                default_value='\\'
            ),
            CommandParameter(
                name="value_name",
                cli_name="Name",
                display_name="Name",
                type=ParameterType.String,
                description='Registry value to write to.',
                default_value='',
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=3
                    ),
                ]),
            CommandParameter(
                name="value_value",
                cli_name="Value",
                display_name="Value",
                type=ParameterType.String,
                description='New value to store in the above registry value.',
                default_value='',
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=4
                    ),
                ]),
        ]

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

    hiveMap = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKEY_CURRENT_USER": "HKCU",
        "HKEY_USERS": "HKU",
        "HKEY_CLASSES_ROOT": "HKCR",
        "HKEY_CURRENT_CONFIG": "HKCC"
    }

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary=dictionary_arguments)
        hive = self.get_arg("hive")
        parts = hive.split("\\")
        hiveClean = parts[0].replace(":", "").strip().upper()
        if hiveClean in self.hiveMap.keys():
            self.add_arg("hive", self.hiveMap[hiveClean])
        elif hiveClean in ["HKLM", "HKCU", "HKU", "HKCR", "HKCC"]:
            self.add_arg("hive", hiveClean)
        else:
            raise Exception("Invalid hive: " + hiveClean)
        if len(parts) > 1:
            self.add_arg("value_value", self.get_arg("value_name"))
            self.add_arg("value_name", self.get_arg("key"))
            self.add_arg("key", "\\".join(parts[1:]))

    async def parse_arguments(self):
        cmds = self.split_commandline()
        if len(cmds) != 3:
            raise Exception("Failed to parse command line arguments. Expected two arguments, got {}\n\tUsage: {}".format(cmds, RegWriteValueBase.help_cmd))

        parts = cmds[0].split("\\")
        hiveClean = parts[0].replace(":", "").strip().upper()
        if hiveClean in self.hiveMap.keys():
            self.add_arg("hive", self.hiveMap[hiveClean])
        elif hiveClean in ["HKLM", "HKCU", "HKU", "HKCR", "HKCC"]:
            self.add_arg("hive", hiveClean)
        else:
            raise Exception("Invalid hive: " + hiveClean)
        self.add_arg("key", "\\".join(parts[1:]))
        self.add_arg("value_name", cmds[1])
        self.add_arg("value_value", cmds[2])


class RegWriteValueBase(CommandBase):
    cmd = "reg_write_value"
    needs_admin = False
    help_cmd = "reg_write_value [key] [value_name] [new_value]"
    description = "Write a new value to the [value_name] value under the specified registry key [key].\n\nEx: reg_write_value HKLM:\\ '' 1234"
    version = 2
    author = "@djhohnstein"
    argument_class = RegWriteValueArguments
    attackmapping = ["T1547", "T1037", "T1546", "T1574", "T1112", "T1003"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-Hive {} -Key {} -Name '{}' -Value '{}'".format(taskData.args.get_arg("hive"),
                                                                                taskData.args.get_arg("key"),
                                                                                taskData.args.get_arg("value_name"),
                                                                                taskData.args.get_arg("value_value"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp