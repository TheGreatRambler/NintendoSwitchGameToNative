#!C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.8_qbz5n2kfra8p0\python.exe
# EASY-INSTALL-ENTRY-SCRIPT: 'setuptools==41.2.0','console_scripts','easy_install'
__requires__ = 'setuptools==41.2.0'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('setuptools==41.2.0', 'console_scripts', 'easy_install')()
    )
