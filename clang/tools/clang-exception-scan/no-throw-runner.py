import os
import json
import shutil
import subprocess as sp
import sys


class ExceptionScan:
    def __init__(self, scanner_binary):
        self._cmake_lists_txt = "CMakeLists.txt"
        self._compile_commands_json = "compile_commands.json"
        self._pane_build_folder = "pane-build"
        self._cmake_export_command = "cmake .. -D CMAKE_EXPORT_COMPILE_COMMANDS=ON"
        self._path_to_exception_scan = scanner_binary
        self._output_folder = "outputs"

        self._cwd = sp.getoutput("pwd")

    def new_repo_scan(self, repo_uris):
        for repo_uri in repo_uris:
            print(f"Repo: {repo_uri}")
            self._git_clone(repo_uri=repo_uri)
            new_repo_name = self._get_new_repository_name(repo_uri=repo_uri)

            if self._is_cmake_lists_exists(repo_name=new_repo_name):
                path_to_pane_folder = os.path.join(
                    self._cwd, new_repo_name, self._pane_build_folder
                )

                self._create_folder(folder_path=path_to_pane_folder)
                self._run_cmake_cmd(pane_path=path_to_pane_folder)

                self._cpy_compile_commands_json(repo_name=new_repo_name)
                self._get_files_from_cc_json(repo_name=new_repo_name)

    def _git_clone(self, repo_uri):
        sp.run(["git", "clone", repo_uri])

    def _get_new_repository_name(self, repo_uri):
        return repo_uri.split("/")[-1][:-4]

    def _is_cmake_lists_exists(self, repo_name):
        return os.path.isfile(os.path.join(self._cwd, repo_name, self._cmake_lists_txt))

    def _create_folder(self, folder_path):
        os.makedirs(folder_path, exist_ok=True)

    def _run_cmake_cmd(self, pane_path):
        os.system(f"cd {pane_path} && {self._cmake_export_command}")

    def _cpy_compile_commands_json(self, repo_name):
        cc_src_path = os.path.join(
            self._cwd, repo_name, self._pane_build_folder, self._compile_commands_json
        )
        cc_dst_path = os.path.join(self._cwd, repo_name, self._compile_commands_json)
        shutil.copy(cc_src_path, cc_dst_path)

    def _get_files_from_cc_json(self, repo_name):
        with open(
            os.path.join(self._cwd, repo_name, self._compile_commands_json), "r"
        ) as cc_json_file:
            cc_content = json.load(cc_json_file)

        self._gen_output_with_scan(
            files_path=[elem["file"] for elem in cc_content], repo_name=repo_name
        )

    def _gen_output_with_scan(self, files_path, repo_name):
        self._create_folder(
            folder_path=os.path.join(self._cwd, repo_name, self._output_folder)
        )

        for file_path in files_path:
            outfile_name = f'{file_path.split("/")[-1].split(".")[0]}.txt'
            outfile_path = os.path.join(
                self._cwd, repo_name, self._output_folder, outfile_name
            )
            os.system(f"{self._path_to_exception_scan} {file_path} &>{outfile_path}")
        print()
        print("OUTPUT FILES EXCEPTION SCAN FINISHED")


# repo_uri = 'https://github.com/apache/xerces-c.git'
repo_uris = [
    "https://github.com/leethomason/tinyxml2.git",
    "https://github.com/webmproject/libwebm.git",
    "https://github.com/bitcoin/bitcoin.git",
]

x_scan = ExceptionScan(sys.argv[1])
x_scan.new_repo_scan(repo_uris=repo_uris)
