#! /usr/bin/python2
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Controlling targets via IPMI
----------------------------

This module implements multiple objects that can be used to control a
target's power or serial console via IPMI.

"""

import logging
import os
import pprint
import subprocess
import time

import commonl
import commonl.requirements
import ttbl.power
import ttbl.console

import pyghmi.ipmi.command

# FIXME: retry ops if the session has timeout/disconnectde, just redo it
# we get  pyghmi.exc.IpmiException('Session no longer connected')

class pci(ttbl.power.impl_c, ttbl.tt_power_control_impl):

    """
    Power controller to turn on/off a server via IPMI

    :param str bmc_hostname: host name or IP address of the BMC
      controller for the host whose power is to be controller.
    :param str user: (optional) username to use to login
    :param str password: (optional) password to use to login

    This is normally used as part of a power rail setup, where an
    example configuration in /etc/ttbd-production/conf_*.py that would
    configure the power switching of a machine that also has a serial
    port would look like:

    >>> ttbl.config.target_add(
    >>>      ttbl.tt.tt_serial(
    >>>          "machine1",
    >>>          power_control = [
    >>>              ttbl.cm_serial.pc(),
    >>>              ttbl.ipmi.pci("bmc_admin:secret@server1.internal.net"),
    >>>          ],
    >>>          serial_ports = [
    >>>              "pc",
    >>>              { "port": "/dev/tty-machine1", "baudrate": 115200 },
    >>>          ]),
    >>>     tags = {
    >>>         'linux': True,
    >>>         'bsp_models': { 'x86_64': None },
    >>>         'bsps': {
    >>>             'x86_64': {
    >>>                 'linux': True,
    >>>                 'console': 'x86_64',
    >>>             }
    >>>         },
    >>>     },
    >>>     target_type = "Brand Model")

    .. warning:: putting BMCs on an open network is not a good idea;
                 it is recommended they are only exposed to an
                  :ref:`infrastructure network <separated_networks>`

    :params str hostname: *USER[:PASSWORD]@HOSTNAME* of where the IPMI BMC is
      located
    """
    def __init__(self, hostname):
        ttbl.tt_power_control_impl.__init__(self)
        ttbl.power.impl_c.__init__(self, paranoid = True)
        user, password, hostname = commonl.split_user_pwd_hostname(hostname)
        self.hostname = hostname
        self.user = user
        self.password = password
        self.bmc = None
        self.power_on_recovery = True

    def _setup(self):
        # this can run in multiple processes, so make sure this is
        # setup for this process each time we connect, because we
        # don't know how long this is going to be open and the session
        # expires
        self.bmc = pyghmi.ipmi.command.Command(self.hostname,
                                               self.user, self.password)
        self.bmc.wait_for_rsp(5)	# timeout after seconds of inactivity

    def on(self, target, component):
        self._setup()
        self.bmc.set_power('on', wait = True)

    def off(self, target, component):
        self._setup()
        self.bmc.set_power('off', wait = True)

    def get(self, target, component):
        self._setup()
        data = self.bmc.get_power()
        state = data.get('powerstate', None)
        if state == 'on':
            return True
        elif state == 'off':
            return False
        else:
            target.log.info("%s: ipmi %s@%s get_power returned no state: %s",
                            component, self.user, self.hostname,
                            pprint.pformat(data))
            return None

    def pre_power_pos_setup(self, target):
        if target.fsdb.get("pos_mode") == 'pxe':
            target.log.error("POS boot: telling system to boot network")
            self.bmc.set_bootdev("network")


    # COMPAT: old interface, ttbl.tt_power_control_impl
    def power_on_do(self, target):
        return self.on(target, "n/a")

    def power_off_do(self, target):
        return self.off(target, "n/a")

    def power_get_do(self, target):
        # this reports None because this is is just a delay loop
        return None


class pci_ipmitool(ttbl.power.impl_c, ttbl.tt_power_control_impl):
    """
    Power controller to turn on/off a server via IPMI

    Same as :class:`pci`, but executing *ipmitool* in the shell
    instead of using a Python library.

    """
    def __init__(self, hostname):
        ttbl.tt_power_control_impl.__init__(self)
        ttbl.power.impl_c.__init__(self, paranoid = True)
        user, password, hostname = commonl.split_user_pwd_hostname(hostname)
        self.hostname = hostname
        self.user = user
        self.bmc = None
        self.env = dict()
        # If I change the argument order, -E doesn't work ok and I get
        # password asked in the command line
        self.cmdline = [
            "ipmitool",
            "-H", hostname
        ]
        if user:
            self.cmdline += [ "-U", user ]
        self.cmdline += [ "-E", "-I", "lanplus" ]
        if password:
            self.env['IPMI_PASSWORD'] = password
        self.timeout = 20
        self.wait = 0.5

    def _run(self, target, command):
        try:
            result = subprocess.check_output(
                self.cmdline + command, env = self.env, shell = False,
                stderr = subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            target.log.error("ipmitool %s failed: %s",
                             " ".join(command), e.output)
            raise
        return result.rstrip()	# remove trailing NLs


    def on(self, target, _component):
        self._run(target, [ "chassis", "power", "on" ])

    def off(self, target, _component):
        self._run(target, [ "chassis", "power", "off" ])

    def get(self, target, component):
        result = self._run(target, [ "chassis", "power", "status" ])
        if 'Chassis Power is on' in result:
            return True
        elif 'Chassis Power is off' in result:
            return False
        target.log.error("%s: ipmtool state returned unknown message: %s"
                         % (component, result))
        return None

    def pre_power_pos_setup(self, target):
        # we use bootparam/set/bootflag since it is working much
        # better, because we seem not to be able to get the system to
        # acknowledge the BIOS boot order
        if target.fsdb.get("pos_mode") == 'pxe':
            target.log.error("POS boot: telling system to boot network")
            # self._run(target, [ "chassis", "bootdev", "pxe" ])
            self._run(target, [ "chassis", "bootparam",
                                "set", "bootflag", "force_pxe" ])
        else:
            self._run(target, [ "chassis", "bootparam",
                                "set", "bootflag", "force_disk" ])


    # COMPAT: old interface, ttbl.tt_power_control_impl
    def power_on_do(self, target):
        return self.on(target, "n/a")

    def power_off_do(self, target):
        return self.off(target, "n/a")

    def power_get_do(self, target):
        # this reports None because this is is just a delay loop
        return None


class sol_console_pc(ttbl.power.socat_pc, ttbl.console.generic_c):
    """
    Implement a serial port over IPMI's Serial-Over-Lan protocol

    This class implements two interfaces:

    - power interface: to start an IPMI SoL recorder in the
      background as soon as the target is powered on.

      The power interface is implemented by subclassing
      :class:`ttbl.power.socat_pc`, which starts *socat* as daemon to
      serve as a data recorder and to pass data to the serial port
      from the read file. It is configured to to start *ipmitool* with
      the *sol activate* arguments which leaves it fowarding traffic
      back and forth.

      Anything read form the serial port is written to the
      *console-NAME.read* file and anything written to it is written
      to *console-NAME.write* file, which is sent to the serial port.

    - console interface: interacts with the console interface by
      exposing the data recorded in *console-NAME.read* file and
      writing to the *console-NAME.write* file.

    :params str hostname: *USER[:PASSWORD]@HOSTNAME* of where the IPMI BMC is
      located

    Look at :class:`ttbl.console.generic_c` for a description of
    *chunk_size* and *interchunk_wait*. This is in general needed when
    whatever is behind SSH is not doing flow control and we want the
    server to slow down sending things.

    For example, create an IPMI recoder console driver and insert it
    into the power rail (its interface as power control makes it be
    called to start/stop recording when the target powers on/off) and
    then it is also registered as the target's console:

    >>> sol0_pc = ttbl.console.serial_pc(console_file_name)
    >>>
    >>> ttbl.config.targets[name].interface_add(
    >>>     "power",
    >>>     ttbl.power.interface(
    >>>         ...
    >>>         sol0_pc,
    >>>         ...
    >>>     )
    >>> ttbl.config.targets[name].interface_add(
    >>>     "console",
    >>>     ttbl.console.interface(
    >>>         sol0 = sol0_pc,
    >>>         default = "sol0",
    >>>     )
    >>> )

    """
    def __init__(self, hostname,
                 precheck_wait = 0.5,
                 chunk_size = 5, interchunk_wait = 0.1):
        assert isinstance(hostname, basestring)
        ttbl.console.generic_c.__init__(self, chunk_size = chunk_size,
                                        interchunk_wait = interchunk_wait)
        ttbl.power.socat_pc.__init__(
            self,
            "PTY,link=console-%(component)s.write,rawer"
            "!!CREATE:console-%(component)s.read",
            "EXEC:'/usr/bin/ipmitool -H %(hostname)s -U %(username)s -E"
            " -I lanplus sol activate',sighup,sigint,sigquit",
            precheck_wait = precheck_wait,
        )
        user, password, hostname = commonl.split_user_pwd_hostname(hostname)
        # pass those fields to the socat_pc templating engine
        self.kws['hostname'] = hostname
        self.kws['username'] = user
        self.kws['password'] = password
        if password:
            self.env_add['IPMITOOL_PASSWORD'] = password

    def on(self, target, component):
        # if there is someone leftover reading, kick them out, there can
        # be only one
        env = dict(os.environ)
        env.update(self.env_add)
        subprocess.call(	# don't check, we don't really care
            [
                "/usr/bin/ipmitool", "-H", self.kws['hostname'],
                "-U", self.kws['username'], "-E",
                "-I", "lanplus", "sol", "deactivate",
                #"-N", "10", "usesolkeepalive" # dies frequently
            ],
            stderr = subprocess.STDOUT,
            bufsize = 0,
            shell = False,
            universal_newlines = False,
            env = env,
        )
        ttbl.power.socat_pc.on(self, target, component)

    # console interface; state() implemented by generic_c
    def enable(self, target, component):
        return self.on(target, component)

    def disable(self, target, component):
        return self.off(target, component)


class sol_ssh_console_pc(ttbl.console.ssh_pc):
    """
    IPMI SoL over SSH console

    This augments :class:`ttbl.console.ssh_pc` in that it will first
    disable the SOL connection to avoid conflicts with other users.

    This forces the input into the SSH channel to the BMC to be
    chunked each five bytes with a 0.1 second delay in between. This
    seems to gives most BMCs a breather re flow control.

    :params str hostname: *USER[:PASSWORD]@HOSTNAME* of where the IPMI BMC is
      located
    """
    def __init__(self, hostname, ssh_port = 22,
                 chunk_size = 5, interchunk_wait = 0.1):
        ttbl.console.ssh_pc.__init__(self, hostname,
                                     port = ssh_port, chunk_size = chunk_size,
                                     interchunk_wait = interchunk_wait)
        _user, password, _hostname = commonl.split_user_pwd_hostname(hostname)
        if password:
            self.env_add['IPMITOOL_PASSWORD'] = password


    def on(self, target, component):
        # if there is someone leftover reading, kick them out, there can
        # be only one
        env = dict(os.environ)
        env.update(self.env_add)
        subprocess.call(	# don't check, we don't really care
            [
                "/usr/bin/ipmitool", "-H", self.kws['hostname'],
                "-U", self.kws['username'], "-E",
                "-I", "lanplus", "sol", "deactivate",
            ],
            stderr = subprocess.STDOUT,
            env = env,
        )
        ttbl.console.ssh_pc.on(self, target, component)
