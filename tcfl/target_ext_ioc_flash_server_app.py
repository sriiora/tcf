#! /usr/bin/python2
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Flash the target with *ioc_flash_server_app*
--------------------------------------------

"""

import tc
from . import msgid_c

class extension(tc.target_extension_c):
    """
    Extension to :py:class:`tcfl.tc.target_c` to the
    *ioc_flash_server_app* command to a target on the server in a safe
    way.

    To configure this interface on a target, see
    :class:`ttbl.ioc_flash_server_app.interface`.
    """

    def __init__(self, target):
        if not 'ioc_flash_server_app' in target.rt.get('interfaces', []):
            raise self.unneeded
        tc.target_extension_c.__init__(self, target)

    def run(self, mode, filename, generic_id = None, baudrate = None):
        """
        Run the *ioc_flash_server_app* command on the target in the
        server in a safe way.

        :param str mode: mode to use, corresponds to ``-MODE`` in the
          command line tool
        :param str filename: name of file to flash (already uploader
          to the USER repository in the server)
        :param str generic_id: when the mode is *generic*, the *ID* to
          use.
        :param str baudrate: (optional)
        """
        self.target.report_info("running", dlevel = 1)
        r = self.target.ttbd_iface_call(
            "ioc_flash_server_app", "run", method = "PUT",
            mode = mode, filename = filename, generic_id = generic_id,
            baudrate = baudrate)
        self.target.report_info("ran",
                                { 'diagnostics': r['diagnostics'] },
                                dlevel = 2)


def _cmdline_ioc_flash_server_app(args):
    with msgid_c("cmdline"):
        target = tc.target_c.create_from_cmdline_args(
            args, iface = "ioc_flash_server_app")
        target.ioc_flash_server_app.run(args.mode, args.filename,
                                        args.id, args.baudrate)

def _cmdline_setup(argsp):
    ap = argsp.add_parser("ioc_flash_server_app",
                          help = "Run ioc_flash_server_app command")
    ap.add_argument("target", metavar = "TARGET", action = "store",
                    default = None, help = "Target's name")
    ap.add_argument("mode", action = "store",
                    type = str, help = "Execution mode (maps to -MODE "
                    "in the command line tool)",
                    default = None)
    ap.add_argument("filename", action = "store",
                    type = str, help = "Filename to flash (must have present "
                    "in the server's user storage space)",
                    default = None)
    ap.add_argument("--baudrate", "-b", action = "store",
                    type = str, help = "Baudrate to use (optional, defaults "
                    "to %(default)s)",
                    default = "115200")
    ap.add_argument("id", action = "store", nargs = "?",
                    type = str, help = "Generic ID for -w command",
                    default = None)
    ap.set_defaults(func = _cmdline_ioc_flash_server_app)
