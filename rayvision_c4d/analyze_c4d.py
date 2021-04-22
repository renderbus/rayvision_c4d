# -*- coding: utf-8 -*-
"""A interface for c4d."""

# Import built-in models
from __future__ import print_function
from __future__ import unicode_literals

import base64
import hashlib
import logging
import os
import sys
import time
from builtins import str

from rayvision_c4d.constants import PACKAGE_NAME
from rayvision_c4d.get_preferences import GetInstallPath
from rayvision_log import init_logger
from rayvision_utils import constants
from rayvision_utils import utils
from rayvision_utils.cmd import Cmd
from rayvision_utils.exception import tips_code
from rayvision_utils.exception.exception import AnalyseFailError, CGFileNotExistsError

VERSION = sys.version_info[0]


class AnalyzeC4d(object):
    def __init__(self, cg_file, software_version, project_name,
                 plugin_config, render_software="CINEMA 4D", render_layer_type="0",
                 input_project_path=None, local_os=None, workspace=None,
                 custom_exe_path=None,
                 platform="2",
                 logger=None,
                 log_folder=None,
                 log_name=None,
                 log_level="DEBUG"
                 ):
        """Initialize and examine the analysis information.

        Args:
            cg_file (str): Scene file path.
            software_version (str): Software version.
            project_name (str): The project name.
            plugin_config (dict): Plugin information.
            render_software (str): Software name, CINEMA 4D by default.
            render_layer_type (str): 0 is render layer, 1 is render setup.
            input_project_path (str): The working path of the scenario.
            local_os (str): System name, linux or windows.
            workspace (str): Analysis out of the result file storage path.
            custom_exe_path (str): Customize the exe path for the analysis.
            platform (str): Platform num.
            logger (object, optional): Custom log object.
            log_folder (str, optional): Custom log save location.
            log_name (str, optional): Custom log file name.
            log_level (string):  Set log level, example: "DEBUG","INFO","WARNING","ERROR".
        """
        self.logger = logger
        if not self.logger:
            init_logger(PACKAGE_NAME, log_folder, log_name)
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(level=log_level.upper())

        self.check_path(cg_file)
        self.cg_file = cg_file

        self.render_software = render_software
        self.input_project_path = input_project_path or ""
        self.render_layer_type = render_layer_type
        self.software_version = software_version
        self.project_name = project_name
        self.plugin_config = plugin_config

        local_os = self.check_local_os(local_os)
        self.local_os = local_os
        self.tmp_mark = str(int(time.time()))
        workspace = os.path.join(self.check_workspace(workspace),
                                 self.tmp_mark)
        if not os.path.exists(workspace):
            os.makedirs(workspace)
        self.workspace = workspace

        if custom_exe_path:
            self.check_path(custom_exe_path)
        self.custom_exe_path = custom_exe_path

        self.platform = platform

        self.task_json = os.path.join(workspace, "task.json")
        self.tips_json = os.path.join(workspace, "tips.json")
        self.asset_json = os.path.join(workspace, "asset.json")
        self.upload_json = os.path.join(workspace, "upload.json")
        self.analyse_log_path = os.path.join(workspace, "analyze.log")
        self.tips_info = {}
        self.task_info = {}
        self.asset_info = {}
        self.upload_info = {}

    @staticmethod
    def check_path(tmp_path):
        """Check if the path exists."""
        if not os.path.exists(tmp_path):
            raise CGFileNotExistsError("{} is not found".format(tmp_path))

    def add_tip(self, code, info):
        """Add error message.
        
        Args:
            code (str): error code.
            info (str or list): Error message description.

        """
        if isinstance(info, str):
            self.tips_info[code] = [info]
        elif isinstance(info, list):
            self.tips_info[code] = info
        else:
            raise Exception("info must a list or str.")

    def save_tips(self):
        """Write the error message to tips.json."""
        utils.json_save(self.tips_json, self.tips_info, ensure_ascii=False)

    @staticmethod
    def check_local_os(local_os):
        """Check the system name.

        Args:
            local_os (str): System name.

        Returns:
            str

        """
        if not local_os:
            if "win" in sys.platform.lower():
                local_os = "windows"
            else:
                local_os = "linux"
        return local_os

    def check_workspace(self, workspace):
        """Check the working environment.

        Args:
            workspace (str):  Workspace path.

        Returns:
            str: Workspace path.

        """
        if not workspace:
            if self.local_os == "windows":
                workspace = os.path.join(os.environ["USERPROFILE"], "renderfarm_sdk")
            else:
                workspace = os.path.join(os.environ["HOME"], "renderfarm_sdk")
        else:
            self.check_path(workspace)

        return workspace

    def analyse_cg_file(self):
        """Analyse cg file.

        Analyze the scene file to get the path to the startup file of the CG
        software.

        """
        # Find the version from the cg file
        if VERSION == 3:
            version = self.check_version3(self.cg_file)
        else:
            version = self.check_version2(self.cg_file)

        if int(float(version)) != int(float(self.software_version)):
            self.add_tip(tips_code.CG_NOTMATCH, "{0} {1}".format(
                self.render_software, self.software_version))
            self.save_tips()

        # Find the installation path with the version
        if self.custom_exe_path is not None:
            exe_path = self.custom_exe_path
        else:
            exe_path = self.find_location()

        return exe_path

    def write_task_json(self):
        """The initialization task.json."""
        constants.TASK_INFO["task_info"]["input_cg_file"] = self.cg_file.replace("\\", "/")
        constants.TASK_INFO["task_info"]["input_project_path"] = self.input_project_path.replace("\\", "/")
        constants.TASK_INFO["task_info"]["render_layer_type"] = self.render_layer_type
        constants.TASK_INFO["task_info"]["project_name"] = self.project_name
        constants.TASK_INFO["task_info"]["cg_id"] = "2005"
        constants.TASK_INFO["task_info"]["os_name"] = "1" if self.local_os == "windows" else "0"
        constants.TASK_INFO["task_info"]["platform"] = self.platform
        constants.TASK_INFO["software_config"] = {
            "plugins": self.plugin_config,
            "cg_version": self.software_version,
            "cg_name": self.render_software
        }
        utils.json_save(self.task_json, constants.TASK_INFO)

    def check_result(self):
        """Check that the analysis results file exists."""
        for json_path in [self.task_json, self.asset_json,
                          self.tips_json]:
            if not os.path.exists(json_path):
                msg = "Json file is not generated: {0}".format(json_path)
                return False, msg
        return True, None

    def get_file_md5(self, file_path):
        """Generate the md5 values for the scenario."""
        hash_md5 = hashlib.md5()
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file_path_f:
                while True:
                    data_flow = file_path_f.read(8096)
                    if not data_flow:
                        break
                    hash_md5.update(data_flow)
        return hash_md5.hexdigest()

    def write_upload_json(self):
        """Generate the upload.json."""
        assets = self.asset_info["asset"]
        upload_asset = []

        self.upload_info["scene"] = [
            {
                "local": self.cg_file.replace("\\", "/"),
                "server": utils.convert_path(self.cg_file),
                "hash": self.get_file_md5(self.cg_file)
            }
        ]

        for path in assets:
            resources = {}
            local = path.split("  (mtime")[0]
            server = utils.convert_path(local)
            resources["local"] = local.replace("\\", "/")
            resources["server"] = server
            upload_asset.append(resources)

        # Add the cg file to upload.json
        upload_asset.append({
            "local": self.cg_file.replace("\\", "/"),
            "server": utils.convert_path(self.cg_file)
        })

        self.upload_info["asset"] = upload_asset

        utils.json_save(self.upload_json, self.upload_info)

    def __copy_file(self, src, dst):
        copy_cmd = 'xcopy /s /y /f /e "%s" "%s"' % (src, dst)
        print('Copy command: [%s]' % copy_cmd)
        os.system(copy_cmd)

    def update_pyp_script(self, exe_path, cg_ver):
        print('Update analyze pyp...')
        curr_dir = os.path.dirname(__file__)
        base_dir = os.path.abspath(curr_dir)

        src_plugin = os.path.join(base_dir, 'tool')

        maxon_temp_path = os.path.join(os.getenv('APPDATA'), 'MAXON')

        if not os.path.exists(maxon_temp_path):
            os.makedirs(maxon_temp_path)

        flag = False
        for dir in os.listdir(maxon_temp_path):
            lower_dir = dir.lower()
            lower_inst = os.path.basename(os.path.dirname(exe_path)).lower()
            lower_ver = cg_ver.lower()
            print(lower_dir, lower_inst, lower_ver)
            if lower_dir.startswith(lower_ver) or lower_dir.startswith(lower_inst):
                flag = True
                maxon_plugin_path = os.path.join(maxon_temp_path, dir, 'plugins')

                if not os.path.exists(maxon_plugin_path):
                    os.makedirs(maxon_plugin_path)
                else:
                    try:
                        os.remove(os.path.join(maxon_plugin_path, 'RBAnalyzer.pyp'))
                        os.system('del /q /s %s\\python26\\*' % maxon_plugin_path)
                        os.system('del /q /s %s\\python27\\*' % maxon_plugin_path)
                        os.system('del /q /s %s\\python37\\*' % maxon_plugin_path)
                    except:
                        pass

                print('Copy pyp: from [%s] to [%s]' % (src_plugin, maxon_plugin_path))

                try:
                    self.__copy_file(src_plugin, maxon_plugin_path)
                    print('RBAnalyzer.pyp was updated...')
                except:
                    pass

        if not flag:
            path_finder = GetInstallPath()
            pref_path_inst = path_finder.install_path(os.path.dirname(exe_path))
            if not os.path.exists(pref_path_inst):
                os.makedirs(pref_path_inst)

            flag = self.update_pyp_script(exe_path, cg_ver)

        return flag

    def analyse(self, exe_path):
        """Build a cmd command to perform an analysis scenario.

        Args:
            exe_path (bool): Do you not generate an upload,json file.

        Raises:
            AnalyseFailError: Analysis scenario failed.

        """
        if not os.path.exists(exe_path):
            self.logger.error("Please enter the c4d software absolute path")
            raise AnalyseFailError

        cg_ver = '{} {}'.format(self.render_software, self.software_version)  # Cinema 4D R19
        if not self.update_pyp_script(exe_path, cg_ver):
            print('[ERROR] MAXON appdata "%appdata%/MAXON" not found')
            raise ValueError('MAXON appdata not found')

        self.write_task_json()

        print('Analyze cg file: [%s]' % self.cg_file)
        if sys.version_info.major == 2:
            cg_file = base64.b64encode(bytes(self.cg_file)).decode("utf-8")
        else:
            cg_file = base64.b64encode(bytes(self.cg_file, 'utf-8')).decode("utf-8")
        print('Encoded cg file: [%s]' % cg_file)

        if self.local_os == 'windows':
            cmd = ('"{exe_path}" -cg_file="{cg_file}" -task_json="{task_json}" '
                   '-asset_json="{asset_json}" -tips_json="{tips_json}" -upload_json="{upload_json}" '
                   '-log_path="{log_path}" '
                   '-parallel -nogui').format(
                exe_path=exe_path,
                cg_file=cg_file,
                task_json=self.task_json,
                asset_json=self.asset_json,
                tips_json=self.tips_json,
                upload_json=self.upload_json,
                log_path=self.analyse_log_path
            )

        else:
            self.logger.error("c4d does not support linux rendering")

        self.logger.debug(cmd)
        code, _, _ = Cmd.run(cmd, shell=True)
        if code not in [0, 1]:
            self.add_tip(tips_code.UNKNOW_ERR, "")
            self.save_tips()
            raise AnalyseFailError

        # Determine whether the analysis is successful by
        #  determining whether a json file is generated.
        status, msg = self.check_result()
        if status is False:
            self.add_tip(tips_code.UNKNOW_ERR, msg)
            self.save_tips()
            raise AnalyseFailError(msg)

        self.tips_info = utils.json_load(self.tips_json)
        self.asset_info = utils.json_load(self.asset_json)
        self.task_info = utils.json_load(self.task_json)
