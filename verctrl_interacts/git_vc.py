"""Functions for carrying out limited list of Git commands.
"""

import os
import re
import logging
from git import Git
from git import Repo
from git import Actor
from git import GitError


logger = logging.getLogger(f"routers_dns_autogen.{__name__}")


# Depending on the environment, "StrictHostKeyChecking=yes" might
# be desired.
SSH_ENV = {"GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=accept-new"}


def git_pull(repo_dir: str, repo_url: str) -> None:
    """Performs either the git pull or git clone operation.

    Performs the git pull if git repo directory exists
    or git clone if the repo dir is missing.
    Transfer protocol is SSH.

    Args:
        repo_dir: Path of the repo directory.

        repo_url: Git repo URL.

    Raises:
        GitError: Git operation error.
    """

    if os.path.isdir(repo_dir):
        logger.info(f'git fetch for "{repo_dir}"')

        try:
            Git(repo_dir).fetch(env=SSH_ENV)
        except GitError as err:
            logger.error(f"git fetch failed: {err!r}")
            raise

        try:
            # Do not try to merge empty repos.
            if Repo(repo_dir).remotes.origin.refs:
                logger.info(f'git merge for "{repo_dir}"')
                Git(repo_dir).merge()
        except GitError as err:
            logger.error(f"git merge failed: {err!r}")
            raise

    else:
        logger.info(f'"{repo_dir}" missing. Git clone from "{repo_url}"')
        try:
            Repo.clone_from(repo_url, repo_dir, env=SSH_ENV)
        except GitError as err:
            logger.error(f"git clone failed: {err!r}")
            raise


def git_commit(
    repo_dir: str, repo_url: str, email: str, commit_msg: str
) -> None:
    """Performs the git commit operation.

    Each changed file in repo is committed. Transfer protocol is SSH.

    Args:
        repo_dir: Path of the repo directory.

        repo_url: Git repo URL.

        email: E-mail address of the git commit author.

        commit_msg: Git commit message.

    Raises:
        GitError: Git operation error.
    """

    try:
        # Add an empty file to the staging area for each untracked file
        # so that the Git(repo_dir).diff() compares the untracked file
        # against its empty version in the staging area.
        Git(repo_dir).add("--intent-to-add", ".")
        changed_files = Git(repo_dir).diff(None, name_only=True)
        # changed_files is a string where changed file names are
        # separated with a newline.
        # In case there are no changes to files, then the changed_files
        # will be an empty string and splitting an empty string with a
        # specified separator returns ['']:
        # https://docs.python.org/3.10/library/stdtypes.html#str.split
        changed_files = [f for f in changed_files.split("\n") if f != ""]
        for changed_file in changed_files:
            logger.info(
                "git add for " f'"{changed_file}" in repo "{repo_dir}"'
            )
            Git(repo_dir).add(changed_file)
            logger.info(
                "git commit for " f'"{changed_file}" in repo "{repo_dir}"'
            )
            if not commit_msg:
                commit_message = (
                    f"! {changed_file} automatically "
                    f'by {email.split("@")[0]}'
                )
            else:
                commit_message = commit_msg

            author = Actor(email.split("@")[0], email)
            Repo(repo_dir).index.commit(
                commit_message, author=author, committer=author
            )

        # Push only if the local branch is ahead.
        aheads = list(Repo(repo_dir).iter_commits("origin/master..master"))
        if aheads:
            logger.info(f'git push for "{repo_dir}"')
            Repo(repo_dir).remote(name="origin").push(env=SSH_ENV)

    except GitError as err:
        logger.error(f'git commit/push for "{repo_url}" failed: {err!r}')
        raise


def git(
    action: str,
    repos_dir: str,
    repo_url: str,
    email: str = "",
    commit_msg: str = "",
) -> str:
    """Performs supported git operations.

    Args:
        action: Name of the intended git operation.

        repos_dir: Root directory for git repos.

        repo_url: Git repo URL.

        email: E-mail address of the git commit author.

        commit_msg: Git commit message.

    Returns:
        repo_dir: Path of the repo directory found by
            combining the root directory for git repos and
            the name of the git repo from repo URL.

    Raises:
        ValueError: Unsupported git command.
    """

    if action not in ("pull", "commit"):
        logger.error(f'git "{action}" is unknown command')
        raise ValueError

    # Supports both the "ssh://[user@]server/project.git" and
    # "[user@]server:project.git" URL formats with or without
    # "git" suffix.
    if re.match(r"^[\w]+://", repo_url):
        repo_dir = repo_url.split("/")[-1].split(".")[0]
    else:
        repo_dir = repo_url.split(":")[-1].split(".")[0]

    repo_dir = os.path.join(repos_dir, repo_dir)

    if action == "pull":

        git_pull(repo_dir, repo_url)

    elif action == "commit":

        git_commit(repo_dir, repo_url, email, commit_msg)

    return repo_dir
