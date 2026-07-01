import sys, runpy, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
runpy.run_module('src.server', run_name='__main__')
