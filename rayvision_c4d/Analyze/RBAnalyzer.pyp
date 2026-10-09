#!/usr/bin/env python
# -*- coding=utf-8 -*-

import sys
import os
import c4d

# Plugin Information
PLUGIN_ID = 1063942
PLUGIN_NAME = "RayC4dSubmit"
PLUGIN_VERSION = "0.0.2"

# Get current Python version for path selection
PY_VERSION = sys.version_info
defaultencoding = 'utf-8'

# Set default encoding for Python 2.x compatibility
if PY_VERSION[0] == 2:
    if sys.getdefaultencoding() != defaultencoding:
        reload(sys)
        sys.setdefaultencoding(defaultencoding)

def get_python_lib_path():
    """
    Automatically determine Python library path based on interpreter version
    Returns the appropriate subdirectory for current Python version
    """
    major, minor = PY_VERSION[0], PY_VERSION[1]
    
    '''
    if version < 17000:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'python26'))
    elif version < 20000:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'python27x')) # 2.7.9
    elif version < 23000:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'python27')) # 2.7.14
    elif version < 24000:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'python37')) # 3.7.7
    elif version < 2023200:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'python39')) # 3.9.1
    elif version < 2024000:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'python310')) # 3.10.8
    else:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'python311')) # 3.11.4
    
    '''
    
    # Python version mapping for library paths
    if major == 2 and minor <= 6:
        return 'python26'
    elif major == 2 and minor == 7:
        return 'python27'
    elif major == 3 and minor <= 7:
        return 'python37'
    elif major == 3 and minor <= 9:
        return 'python39'
    elif major == 3 and minor <= 10:
        return 'python310'
    elif major == 3 and minor <= 11:
        return 'python311'
    else:
        # Fallback to latest supported version
        print("Warning: Unsupported Python version %d.%d, using python311 fallback" % (major, minor))
        return 'python311'

def setup_python_path():
    """
    Setup Python path for the analyzer module.
    """
    try:
        plugin_dir = os.path.dirname(__file__)
        dev_module_file = find_analyzer_module(plugin_dir, "RBAnalyzer")
        
        if dev_module_file:
            if plugin_dir not in sys.path:
                sys.path.insert(0, plugin_dir)
            print("RBAnalyzer module found: %s" % dev_module_file)
            return True

        python_lib_dir = get_python_lib_path()
        production_path = os.path.join(plugin_dir, python_lib_dir)
        print("Looking for RBAnalyzer module in: %s" % production_path)
        
        if os.path.exists(production_path):
            if production_path not in sys.path:
                sys.path.insert(0, production_path)
            
            prod_module_file = find_analyzer_module(production_path, "RBAnalyzer")
            if prod_module_file:
                print("RBAnalyzer module found: %s" % prod_module_file)
            else:
                # 警告：模块文件在生产路径下也没找到，仍然返回 True，
                # 让后续的 import 语句去触发 ImportError，这样报错信息更明确。
                print("Warning: RBAnalyzer module not found (.pyd or .py) in production path.")
            
            return True
        else:
            print("Error: Python library path not found: %s" % production_path)
            return False
            
    except Exception as e:
        print("Error setting up Python path: %s" % str(e))
        return False


def find_analyzer_module(search_path, module_name):
    """
    Find analyzer module file (.pyd preferred, .py as fallback)
    Returns the full path if found, None otherwise
    """
    # Priority order: .pyd (compiled), .py (source)
    extensions = ['.pyd', '.py']
    
    for ext in extensions:
        module_file = os.path.join(search_path, module_name + ext)
        if os.path.exists(module_file):
            return module_file
    
    return None

def get_task_json_from_args():
    """
    Extract task.json path from command line arguments
    Expected format: --taskjson="path/to/task.json"
    """
    try:
        args = sys.argv
        print("Command line arguments: %s" % args)
        
        for arg in args:
            # Check for --taskjson=value format
            if arg.startswith('--taskjson='):
                task_json_path = arg.split('=', 1)[1]
                # Remove quotes if present
                if task_json_path.startswith('"') and task_json_path.endswith('"'):
                    task_json_path = task_json_path[1:-1]
                elif task_json_path.startswith("'") and task_json_path.endswith("'"):
                    task_json_path = task_json_path[1:-1]
                
                print("Task JSON path from args: %s" % task_json_path)
                return task_json_path
        
        print("Warning: --taskjson argument not found in command line")
        return None
    except Exception as e:
        print("Error parsing command line arguments: %s" % str(e))
        return None

class C4dAnalyzerMessageData(c4d.plugins.MessageData):
    """
    Message plugin to handle command line arguments for C4D scene analysis
    """
    
    def CoreMessage(self, id, bc):
        """
        Handle core messages from Cinema 4D
        """
        return True

def load_json(json_file):
    import json
    with open(json_file, encoding="utf8", errors='ignore') as f:
        json_str = f.read()
        if not json_str.strip():
            d = {}
        elif "}" not in json_str:
            d = {}
        else:
            while not json_str.endswith("}"):
                json_str = json_str[:-1]
            d = json.loads(json_str)
    return d

def run_client_analysis():
    """
    Execute C4D scene analysis in client mode
    """
    try:
        # Setup Python environment
        if not setup_python_path():
            print("Error: Failed to setup Python environment")
            return False
        
        # Get task.json path from command line
        task_json_path = get_task_json_from_args()
        if not task_json_path:
            print("Error: No task.json path provided")
            return False
        
        # Validate task.json file exists
        if not os.path.exists(task_json_path):
            print("Error: Task JSON file not found: %s" % task_json_path)
            return False
        task_json_dict = load_json(task_json_path)
        
        # Import the analyzer module
        try:
            import RBAnalyzer
            print("Successfully imported RBAnalyzer module")
        except ImportError as e:
            print("Error: Failed to import RBAnalyzer module: %s" % str(e))
            return False
        
        # Execute analysis in client mode
        print("=== Starting C4D Scene Analysis (Client Mode) ===")
        print("Python Version: %d.%d.%d" % (PY_VERSION[0], PY_VERSION[1], PY_VERSION[2]))
        print("C4D Version: %d" % c4d.GetC4DVersion())
        print("Task JSON: %s" % task_json_path)
        print()

        if task_json_dict["task_info"].get("channel") == "4":
            success = RBAnalyzer.analyze_c4d_scene(
                mode='api',
                task_json_path=task_json_path,
                output_directory=os.path.dirname(task_json_path)  # Use default client mode directory
            )
        else:
            # Call the secure unified API
            success = RBAnalyzer.analyze_c4d_scene(
                mode='client',
                task_json_path=task_json_path,
                output_directory=None  # Use default client mode directory
            )
        
        if success:
            print("=== Analysis Completed Successfully ===")
            print("Check output directory for generated files:")
            print("- task.json (updated with scene_info)")
            print("- tips.json (error codes)")
            print("- asset.json (asset statistics)")
            print("- asset.txt (asset list)")
            print("- upload.json (upload information)")
            print("- analyze_sucess (success marker)")
        else:
            print("=== Analysis Failed ===")
            print("Please check the error messages above")
        
        return success
        
    except Exception as e:
        print("Error: Analysis execution failed: %s" % str(e))
        return False

def PluginMessage(id, data):
    """
    Global plugin message handler (Required for R19-2025 compatibility)
    Triggered when Cinema 4D processes command line arguments
    """
    if id == c4d.C4DPL_COMMANDLINEARGS:
        try:
            print("=== C4D Analyzer Plugin Activated ===")
            print("Processing command line arguments...")
            
            # Run the client analysis
            success = run_client_analysis()
            
            if success:
                print("Plugin execution completed successfully")
            else:
                print("Plugin execution failed")
                
        except Exception as e:
            print("Plugin error: %s" % str(e))
        finally:
            # Ensure cleanup
            pass
        
        return True
    
    return False

if __name__ == "__main__":
    c4d.plugins.RegisterMessagePlugin(
        id=PLUGIN_ID,
        str=PLUGIN_NAME,
        info=0,
        dat=C4dAnalyzerMessageData()
    )

