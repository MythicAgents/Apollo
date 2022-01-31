from mythic_payloadtype_container.MythicCommandBase import *
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
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = RegQueryArguments
    attackmapping = ["T1012", "T1552"]
    supported_ui_features = ["reg_query"]
    browser_script = BrowserScript(script_name="reg_query", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if task.args.get_arg("key"):
            task.display_params = "-Hive {} -Key {}".format(task.args.get_arg("hive"), task.args.get_arg("key"))
        else:
            task.display_params = "-Hive {}".format(task.args.get_arg("hive"))
        return task

    async def process_response(self, response: AgentResponse):
        pass