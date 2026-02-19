"""
Fetches source code from npm, GitHub, or local paths.
"""

import asyncio
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

from mcpsec.ui import console

async def fetch_source(
    npm: str | None = None,
    github: str | None = None,
    path: str | None = None
) -> str | None:
    """
    Fetch source code from the specified location.
    Returns the path to the directory containing the source code.
    """
    if npm:
        return await _fetch_npm(npm)
    elif github:
        return await _fetch_github(github)
    elif path:
        return _validate_local_path(path)
    return None

async def _fetch_npm(package_name: str) -> str | None:
    """Download and extract an npm package."""
    temp_dir = tempfile.mkdtemp(prefix="mcpsec_npm_")
    console.print(f"  [cyan]Fetching npm package: {package_name}[/cyan]")
    
    try:
        # Resolve npm path (needed for Windows)
        npm_cmd = shutil.which("npm")
        if not npm_cmd:
             # Fallback for Windows if not found but potentially existing as npm.cmd
             if os.name == "nt":
                 npm_cmd = shutil.which("npm.cmd")
        
        if not npm_cmd:
            console.print("  [danger]Error: 'npm' executable not found. Is it installed and in PATH?[/danger]")
            shutil.rmtree(temp_dir)
            return None

        # Run npm pack
        proc = await asyncio.create_subprocess_exec(
            npm_cmd, "pack", package_name,
            cwd=temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            console.print(f"  [danger]Error running npm pack: {stderr.decode()}[/danger]")
            shutil.rmtree(temp_dir)
            return None
            
        # Find the .tgz file
        tgz_file = stdout.decode().strip()
        tgz_path = Path(temp_dir) / tgz_file
        
        if not tgz_path.exists():
            # Sometimes npm pack outputs only filename, sometimes path. 
            # If we can't find it easily, search the dir
            found = list(Path(temp_dir).glob("*.tgz"))
            if found:
                tgz_path = found[0]
            else:
                 console.print(f"  [danger]Could not find packed file for {package_name}[/danger]")
                 shutil.rmtree(temp_dir)
                 return None

        # Extract
        with tarfile.open(tgz_path, "r:gz") as tar:
            tar.extractall(path=temp_dir)
            
        # npm packages usually extract into a 'package' folder
        extracted_path = Path(temp_dir) / "package"
        if extracted_path.exists():
            return str(extracted_path)
            
        return str(temp_dir)

    except Exception as e:
        console.print(f"  [danger]Failed to fetch npm package: {e}[/danger]")
        shutil.rmtree(temp_dir)
        return None

async def _fetch_github(repo_url: str) -> str | None:
    """Clone a GitHub repository."""
    temp_dir = tempfile.mkdtemp(prefix="mcpsec_git_")
    console.print(f"  [cyan]Cloning GitHub repo: {repo_url}[/cyan]")
    
    try:
        git_cmd = shutil.which("git")
        if not git_cmd:
            console.print("  [danger]Error: 'git' executable not found. Is it installed?[/danger]")
            shutil.rmtree(temp_dir)
            return None

        proc = await asyncio.create_subprocess_exec(
            git_cmd, "clone", "--depth", "1", repo_url, temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            console.print(f"  [danger]Error cloning repo: {stderr.decode()}[/danger]")
            shutil.rmtree(temp_dir)
            return None
            
        return str(temp_dir)

    except Exception as e:
        console.print(f"  [danger]Failed to clone repo: {e}[/danger]")
        shutil.rmtree(temp_dir)
        return None

def _validate_local_path(path: str) -> str | None:
    """Validate a local path."""
    p = Path(path).resolve()
    if not p.exists():
        console.print(f"  [danger]Path does not exist: {path}[/danger]")
        return None
    if not p.is_dir():
        console.print(f"  [danger]Path is not a directory: {path}[/danger]")
        return None
    return str(p)

def cleanup_temp(path: str):
    """Clean up temporary directory."""
    if "mcpsec_" in path and os.path.exists(path):
        try:
            # On Windows, sometimes files are locked. Iterate and force remove.
            # But simple rmtree is usually enough for temp dirs if we closed handles.
            # However, if we are inside the dir, we can't delete it.
            # Make sure we are not.
            shutil.rmtree(path, ignore_errors=True)
        except Exception as e:
            console.print(f"  [muted]Warning: Failed to clean up {path}: {e}[/muted]")
