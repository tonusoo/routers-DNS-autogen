"""Functions for carrying out limited list of CVS commands.
"""

import os
import re
import logging
from subprocess import run, CalledProcessError


logger = logging.getLogger(f"routers_dns_autogen.{__name__}")


# Function is not in use, but perhaps it's useful if one is
# using CVS for version control instead of Git. The function is
# from the original version of the script where the reverse zones
# were stored in the CVS.
def cvs(*files, cvsdir, action, commit_message=""):

    warning_flag = 0

    if action not in ("update", "remove", "add", "commit", "diff"):
        warning_flag = 1
        return warning_flag, "invalid option"

    # As there is no modern Python3 library for CVS, then
    # external CVS client(https://cvs.savannah.gnu.org/viewvc/cvs/ccvs/)
    # is used.
    cmd = ["cvs", "-Q"]

    cmd.append(action)

    if action not in ("update", "remove", "diff") and commit_message:
        cmd.append("-m")
        cmd.append(commit_message)

    if action == "update":
        cmd.append("-C")
        # "cvs -Q update -C" will overwrite locally modified files with
        # clean repository copies. However, the locally modified(mtime
        # has changed) files are saved with .#file.revision names. There
        # seems to be no way to change this behavior. Fortunately, "cvs
        # update" will print a "Locally modified <filename> moved to
        # .#<filename>.<cvs_revision>" message when doing so if the
        # '-Q'(really quiet) argument is not specified. This allows one
        # to capture the output of "cvs update -C" and remove the backed
        # up files. That's the reason why '-Q' argument is removed in
        # case of "cvs up". Typically this happens if the content of the
        # file under CVS is overwritten for example in list_to_file() or
        # write_forwards() functions. Even if the content of the file
        # did not change, then the "cvs update -C" for that file will
        # create the unnecessary backup files.
        cmd.remove("-Q")

    if files:
        for file in files:
            try:
                logger.info(f'"cvs {action}" for "{cvsdir}{file}"')
                if action == "diff":
                    # Exit code for 'cvs diff' is >0 both in case of
                    # errors and in case there is a difference between
                    # the local copy and the version in the CVS server.
                    # That's the reason why exit code is not checked.
                    output = run(
                        cmd + [file],
                        cwd=cvsdir,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                else:
                    output = run(
                        cmd + [file],
                        cwd=cvsdir,
                        capture_output=True,
                        text=True,
                        check=True,
                    )

                    # Remove the automatically backed up("-C" in "man
                    # cvs" for more info) files.
                    re_pattern = r"^\(Locally modified .+ moved to (.+)\)$\n"
                    match = re.match(re_pattern, output.stdout, re.M)
                    if match:
                        # Some file names can contain the
                        # directory part.
                        os.remove(
                            cvsdir
                            + "/".join(file.split("/")[:-1])
                            + "/"
                            + match.group(1)
                        )

            except CalledProcessError:
                logger.error(f'"cvs {action}" for "{cvsdir}{file}" failed')
                warning_flag = 1
    else:
        try:
            logger.info(f'"cvs {action}" for "{cvsdir}"')
            output = run(
                cmd, cwd=cvsdir, capture_output=True, text=True, check=True
            )

            re_pattern = r"^\(Locally modified .+ moved to (.+)\)$"
            for line in output.stdout.splitlines():
                match = re.match(re_pattern, line, re.M)
                if match:
                    os.remove(cvsdir + match.group(1))

        except CalledProcessError as err:
            logger.error(f'"cvs {action}" for "{cvsdir}" failed: {err!r}')
            warning_flag = 1

    return warning_flag, output
