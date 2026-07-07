import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

REPO = "ChiChou/XpcScope"
PROJECT_ROOT = Path(__file__).resolve().parent
AGENT_SRC = PROJECT_ROOT / "agent"
AGENT_DST = PROJECT_ROOT / "xpcscope" / "agent" / "_agent.js"


def _get_version():
    for line in (PROJECT_ROOT / "pyproject.toml").read_text().splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    raise RuntimeError("version not found in pyproject.toml")


def _try_npm_build():
    npm = shutil.which("npm")
    if not npm or not (AGENT_SRC / "package.json").exists():
        return False
    try:
        subprocess.check_call([npm, "install"], cwd=str(AGENT_SRC),
                              stdout=sys.stderr, stderr=sys.stderr)
        subprocess.check_call([npm, "run", "build"], cwd=str(AGENT_SRC),
                              stdout=sys.stderr, stderr=sys.stderr)
        return AGENT_DST.exists()
    except (subprocess.CalledProcessError, OSError):
        return False


def _try_download():
    tag = f"v{_get_version()}"
    url = f"https://github.com/{REPO}/releases/download/{tag}/_agent.js"
    sys.stderr.write(f"Downloading _agent.js from {url}\n")
    try:
        AGENT_DST.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, str(AGENT_DST))
        return AGENT_DST.exists()
    except Exception as e:
        sys.stderr.write(f"Download failed: {e}\n")
        return False


def ensure_agent():
    if AGENT_DST.exists():
        return

    sys.stderr.write("_agent.js not found, attempting to build from source...\n")
    if _try_npm_build():
        sys.stderr.write("Agent built successfully.\n")
        return

    sys.stderr.write("npm not available, downloading pre-built agent...\n")
    if _try_download():
        sys.stderr.write("Agent downloaded successfully.\n")
        return

    sys.stderr.write(
        "WARNING: could not build or download _agent.js. "
        "Install Node.js and run 'cd agent && npm install && npm run build', "
        f"or download from https://github.com/{REPO}/releases\n"
    )


class BuildPyWithAgent(build_py):
    def run(self):
        ensure_agent()
        super().run()


setup(cmdclass={"build_py": BuildPyWithAgent})
