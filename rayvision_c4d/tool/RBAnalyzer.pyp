# -*- coding=utf-8 -*-
# author: kanada

import sys,os,c4d

version = c4d.GetC4DVersion()

defaultencoding = 'utf-8'
if sys.getdefaultencoding() != defaultencoding:
    reload(sys)
    sys.setdefaultencoding(defaultencoding)

if version < 17000:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'python26'))
elif version < 20000:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'python27x'))
elif version < 23000:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'python27'))
else:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'python37'))


def PluginMessage(id, data):
    if id==c4d.C4DPL_COMMANDLINEARGS:
        try:
            import RBAnalyzer
        finally:
            pass
        
        return True

    return False