import os
import platform
import re
import subprocess
import tempfile

import lit.formats
import lit.util

from lit.llvm import llvm_config
from lit.llvm.subst import ToolSubst
from lit.llvm.subst import FindTool

# Configuration file for the 'lit' test runner.

# name: The name of this test suite.
config.name = 'clang-exception-scan'

# testFormat: The test format to use to interpret tests.
config.test_format = lit.formats.ShTest(not llvm_config.use_lit_shell)

# suffixes: A list of file extensions to treat as test files.
config.suffixes = ['.cpp', '.test']

# excludes: A list of directories to exclude from the testsuite.
config.excludes = ['CMakeLists.txt', 'README.txt', 'LICENSE.txt']

# test_source_root: The root path where tests are located.
config.test_source_root = os.path.dirname(__file__)

# test_exec_root: The root path where tests should be run.
config.test_exec_root = os.path.join(config.clang_obj_root, 'test')

# Propagate some variables from the host environment.
llvm_config.with_system_environment(['HOME', 'INCLUDE', 'LIB', 'TMP', 'TEMP'])

llvm_config.use_default_substitutions()

# Add clang-exception-scan specific substitutions.
tool_substitutions = [
    ToolSubst('%clang_exception_scan', command=FindTool('clang-exception-scan')),
]
llvm_config.add_tool_substitutions(tool_substitutions)

# For tests that need a JSON compilation database
config.substitutions.append(('%gen_compdb',
    'python3 ' + os.path.join(config.test_source_root, 'gen-compdb.py')))

# Discover the 'clang' and 'clangd' to use.
builtin_include_dir = os.path.join(config.clang_obj_root, 'lib', 'clang',
                                  config.clang_version, 'include')

tools = [
    'clang',
]

llvm_config.add_tool_substitutions(tools, config.clang_tools_dir) 