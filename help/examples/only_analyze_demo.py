# -*- coding: utf-8 -*-
"""only analyze c4d"""

from rayvision_c4d.analyze_c4d import AnalyzeC4d

analyze_info = {
    "cg_file": r"D:\houdini\cg_file\ybt.c4d",
    "workspace": "c:/workspace",
    "software_version": "R22",
    "project_name": "Project1",
    "plugin_config": {}
}

AnalyzeC4d(**analyze_info).analyse(exe_path=r"C:\Program Files\Maxon Cinema 4D R22\Cinema 4D.exe")