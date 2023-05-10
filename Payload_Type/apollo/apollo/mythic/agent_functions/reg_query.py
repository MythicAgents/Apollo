from mythic_container.MythicCommandBase import *
import json


class RegQueryArguments(TaskArguments):

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
                choices=["HKLM", "HKCU", "HKU", "HKCR", "HKCC"]),
            CommandParameter(
                name="key",
                cli_name="Key",
                display_name="Registry Key", 
                type=ParameterType.String,
                description='Registry key to interrogate.', 
                default_value='',
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ]),
        ]


    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split("\\")
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


class RegQuery(CommandBase):
    cmd = "reg_query"
    needs_admin = False
    help_cmd = "reg_query [key]"
    description = "Query registry keys and values for an associated registry key [key]."
    version = 2
    author = "@djhohnstein"
    argument_class = RegQueryArguments
    attackmapping = ["T1012", "T1552"]
    supported_ui_features = ["reg_query"]
    browser_script = BrowserScript(script_name="reg_query", author="@djhohnstein", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        if taskData.args.get_arg("key"):
            response.DisplayParams = "-Hive {} -Key {}".format(taskData.args.get_arg("hive"), taskData.args.get_arg("key"))
        else:
            response.DisplayParams = "-Hive {}".format(taskData.args.get_arg("hive"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp