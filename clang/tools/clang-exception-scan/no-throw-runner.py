import os
import json
import shutil
import shlex
import subprocess as sp
import sys

from pathlib import Path


class CodeCheckerRunner:
    def __init__(self, cc_dir: Path):
        self.cc_dir = cc_dir

    def download(self):
        sp.run(
            [
                "git",
                "clone",
                "https://github.com/Ericsson/CodeChecker",
                self.cc_dir.absolute(),
            ]
        )

    def build(self):
        sp.run(["make", "standalone_package"], cwd=self.cc_dir)

    def log_build(self, build_command):
        comp_db = Path("compile_commands.json")
        sp.run(shlex.split(f'codechecker/build/CodeChecker/bin/CodeChecker log -b "{build_command}" -o {comp_db}'))
        return comp_db


class ExceptionScan:
    def __init__(self, scanner_binary: Path):
        self._cmake_lists_txt = "CMakeLists.txt"
        self._compile_commands_json = "compile_commands.json"
        self._pane_build_folder = "pane-build"
        self._path_to_exception_scan = scanner_binary
        self._output_folder = "outputs"

        self._cwd = sp.getoutput("pwd")

    def default_configure_command(self):
        return "cmake .. -D CMAKE_EXPORT_COMPILE_COMMANDS=ON"

    def new_repo_scan(self, cc_runner: CodeCheckerRunner, repos):
        for repo in repos:
            print(f"Repo: {repo['name']}")

            new_repo_name = self._get_new_repository_name(repo_uri=repo["uri"])
            repo_path = Path(new_repo_name)
            # shutil.rmtree(repo_path)
            self._git_clone(repo_uri=repo["uri"])

            if ('configure_command' in repo):
                build_dir = repo_path
                self._run_custom_cmd(build_dir=build_dir, repo=repo)
                cc_runner.log_build("make")
            else:
                build_dir = repo_path / self._pane_build_folder
                build_dir.mkdir(exist_ok=True)
                self._run_cmake_cmd(build_dir=build_dir, repo=repo)
                self._cpy_compile_commands_json(repo_name=new_repo_name)

            self._get_files_from_cc_json(repo_name=new_repo_name)

    def _git_clone(self, repo_uri):
        sp.run(["git", "clone", repo_uri])

    def _get_new_repository_name(self, repo_uri):
        return repo_uri.split("/")[-1][:-4]

    def _is_cmake_lists_exists(self, repo_name):
        return (Path(repo_name) / self._cmake_lists_txt).is_file()

    def _run_cmake_cmd(self, build_dir, repo):
        configure_command = repo.get(
            "configure_command", self.default_configure_command()
        )
        sp.run(shlex.split(configure_command), cwd=build_dir)

    def _run_custom_cmd(self, build_dir, repo):
        sp.run(shlex.split(repo["configure_command"]), cwd=build_dir)

    def _cpy_compile_commands_json(self, repo_name):
        cc_src_path = (
            Path(repo_name) / self._pane_build_folder / self._compile_commands_json
        )
        cc_dst_path = Path(repo_name) / self._compile_commands_json
        shutil.copy(cc_src_path, cc_dst_path)

    def _get_files_from_cc_json(self, repo_name):
        with open(Path(repo_name) / self._compile_commands_json, "r") as cc_json_file:
            cc_content = json.load(cc_json_file)

        self._gen_output_with_scan(
            files_path=[elem["file"] for elem in cc_content], repo_name=repo_name
        )

    def _gen_output_with_scan(self, files_path, repo_name):
        output_path = Path(repo_name) / self._output_folder
        output_path.mkdir(exist_ok=True)

        for file_path in files_path:
            outfile_name = f'{file_path.split("/")[-1].split(".")[0]}.txt'
            outfile_path = output_path / outfile_name
            os.system(f"{self._path_to_exception_scan} {file_path} &>{outfile_path}")
        print("\nOUTPUT FILES EXCEPTION SCAN FINISHED\n")


repos = [
#     {
#         "name": "FRUT",
#         "uri": "https://github.com/McMartin/FRUT.git",
#     },
     {
         "name": "bitcoin",
         "uri": "https://github.com/bitcoin/bitcoin.git",
         "configure_command": "./autogen.sh && ./configure --disable-wallet --disable-static --disable-tests --without-gui",
     },
]

cc_runner = CodeCheckerRunner(cc_dir=Path("codechecker"))
# cc_runner.download()
# cc_runner.build()

x_scan = ExceptionScan(scanner_binary=Path(sys.argv[1]))
x_scan.new_repo_scan(cc_runner=cc_runner, repos=repos)
