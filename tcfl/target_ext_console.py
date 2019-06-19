#! /usr/bin/python2
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Raw access to the target's serial consoles
------------------------------------------

"""

import contextlib
import curses.ascii
import mmap
import os
import re
import time
import traceback

import requests

import commonl
import tc


class expect_text_on_console_c(tc.expectation_c):
    """
    Object that expectes to find a string or regex in a target's
    serial console.

    See parameter description in builder :meth:`console.expect_text`
    """
    def __init__(self,
                 text_or_regex,
                 console = None,	# default
                 poll_period = 1,
                 timeout = 30,
                 previous_max = 4096,
                 raise_on_timeout = tc.failed_e,
                 raise_on_found = None,
                 name = None,
                 target = None):
        assert isinstance(target, tc.target_c)	# mandatory
        assert isinstance(text_or_regex, (basestring, re._pattern_type))
        assert console == None or isinstance(console, basestring)
        assert timeout == None or timeout >= 0
        assert poll_period > 0
        assert previous_max > 0
        tc.expectation_c.__init__(self, target, poll_period, timeout,
                                  raise_on_timeout = raise_on_timeout,
                                  raise_on_found = raise_on_found)
        assert name == None or isinstance(name, basestring)

        if isinstance(text_or_regex, basestring):
            self.regex = re.compile(re.escape(text_or_regex),
                                    re.MULTILINE)
        elif isinstance(text_or_regex, re._pattern_type):
            self.regex = text_or_regex
        else:
            raise AssertionError(
                "text_or_regex must be a string or compiled regex, got %s" \
                % type(text_or_regex).__name__)
        if name:
            self.name = name
        else:
            # this might get hairy when a regex is just regex that all
            # gets escaped out (looking like _______________). oh well
            self.name = commonl.name_make_safe(self.regex.pattern)

        self.console = console
        if console:
            self.console_name = console
        else:
            self.console_name = "default"
        self.previous_max = previous_max

    #: Maximum amonut of bytes to read on each read iteration in
    #: :meth:`poll`; this is so that if a (broken) target is spewing
    #: gigabytes of data, we don't get stuck here just reading from it.
    max_size = 65536
        
    def poll_context(self):
        # we are polling from target with role TARGET.WANT_NAME from
        # it's console CONSOLE, so this is our context, so anyone
        # who will capture from that reuses the capture.
        # Note we also use this for naming the collateral file
        return '%s.%s.%s' % (self.target.want_name, self.target.id,
                             self.console_name)

    def _poll_init(self, testcase, run_name, buffers_poll):
        # NOTE: this is called with target.lock held

        target = self.target
        filename = buffers_poll.get('filename', None)
        if filename:
            target.report_info(
                "%s/%s: existing console capture context %08x/%s" %
                (run_name, self.name, id(buffers_poll), filename), dlevel = 5)
            return	# polling is initialized!
        # this means we never started reading
        #
        # there will be only a single reader state per testcase,
        # no matter how many expectations are pointed to a
        # target's console--see poll() for how we get there.
        #
        # so then, remove the existing collateral file, register it
        filename = os.path.relpath(testcase.report_file_prefix \
                                   + "console.%s.txt" % self.poll_context())
        with testcase.lock:
            testcase.collateral.add(filename)
        # rename any existing file, we are starting from scratch
        target.report_info(
            "%s/%s: new console capture context %08x/%s" %
            (run_name, self.name, id(buffers_poll), filename), dlevel = 5)
        commonl.rm_f(filename)
        buffers_poll['filename'] = filename

        # how much do we care on previous history? no good way to
        # tell, so we set a sensible default we can alter
        # also, the target could put more data out before we start
        # reading, so this is just an approx
        read_offset = target.console.size()
        if read_offset > self.previous_max:
            read_offset -= self.previous_max
        buffers_poll['read_offset'] = read_offset

        of = open(filename, "a+", 0)
        buffers_poll['of'] = of
        buffers_poll['ofd'] = of.fileno()


    def _poll(self, testcase, run_name, buffers_poll):
        # NOTE: this is called with target.lock held
        target = self.target

        # polling a console happens by reading the remote console into
        # a local file we keep as collateral
        self._poll_init(testcase, run_name, buffers_poll)
        read_offset = buffers_poll['read_offset']
        console_size = target.console.size(self.console)
        # If the target has rebooted, then the console file was
        # truncated to zero and our read offsets changed
        if console_size < read_offset:
            # FIXME: this is a hack until we have a session count
            # here, which monotonically increases in the server each
            # time the thing reboots. Ideally it will be returned as part of
            # read() and size()
            target.report_info(
                "%s/%s: target rebooted (console size %d < read offset %d)"
                " resetting read offset to zero"
                % (run_name, self.name, console_size, read_offset),
                dlevel = 3)
            read_offset = 0
        of = buffers_poll['of']
        ofd = buffers_poll['ofd']

        try:
            ts_start = time.time()
            target.report_info(
                "%s/%s: reading from console %s:%s @%d on %.2fs to %s"
                % (run_name, self.name, target.fullid, self.console_name,
                   read_offset, ts_start, of.name), dlevel = 5)
            # We are dealing with a file as our buffering and accounting
            # system, so because read_to_fd() is bypassing caching, flush
            # first and sync after the read.
            of.flush()
            total_bytes = target.rtb.rest_tb_target_console_read_to_fd(
                ofd, target.rt, self.console,
                read_offset, self.max_size, target.ticket)
            ts_end = time.time()
            of.flush()
            os.fsync(ofd)
            buffers_poll['read_offset'] = read_offset + total_bytes
            target.report_info(
                "%s/%s: read from console %s:%s @%d %dB on %.2fs (%.2fs) to %s"
                % (run_name, self.name, target.fullid, self.console_name,
                   read_offset, total_bytes, ts_end, ts_end - ts_start,
                   of.name),
                dlevel = 4)

        except requests.exceptions.HTTPError as e:
            raise tc.blocked_e(
                "%s/%s: error reading console %s:%s @%dB: %s\n"
                % (run_name, self.name,
                   target.fullid, self.console_name, read_offset, e),
                { "error trace": traceback.format_exc() })

    def poll(self, testcase, run_name, _buffers_poll):
        # polling a console happens by reading the remote console into
        # a local file we keep as collateral

        # We need to make this capture
        # global to all threads in this testcase that might be reading
        # from this target--only deal is that only one at the same
        # time can write to it, shouldn't be a problem--so all the
        # state has to be updated subject to a target specific lock --
        # which now we do not have--so this poll is not specific to
        # the expect() all or to this expectation itself; it is global
        # to the testcase--this is why it uses the testcase buffers,
        # not the buffers provided in the call, to store.

        with testcase.lock:
            context = self.poll_context()
            testcase.buffers.setdefault(context, dict())
            buffers_poll = testcase.buffers[context]

        target = self.target
        with target.lock:
            return self._poll(testcase, run_name, buffers_poll)

    def detect(self, testcase, run_name, _buffers_poll, buffers):
        """
        See :meth:`expectation_c.detect` for reference on the arguments

        :returns: list of squares detected at different scales in
          relative and absolute coordinates, e.g:
        """
        target = self.target

        # see poll() above for why we ignore the poll buffers given by
        # the expect system and take the global testcase buffers
        context = self.poll_context()
        with testcase.lock:
            buffers_poll = testcase.buffers.get(context, None)
        if buffers_poll == None:
            target.report_info('%s/%s: not detecting, no console data yet'
                               % (run_name, self.name))
            return None

        # last time we looked we looked from search_offset
        testcase.tls.buffers.setdefault(context + 'search_offset', 0)
        search_offset = testcase.tls.buffers[context + 'search_offset']

        # this is set if the filename is set
        of = buffers_poll['of']
        ofd = buffers_poll['ofd']
        stat_info = os.fstat(ofd)
        if stat_info.st_size == 0:	# Nothing to read
            return None

        # we mmap because we don't want to (a) read a lot of a huger
        # file line by line and (b) share file pointers -- we'll look
        # to our own offset instead of relying on that. Other
        # expectations might be looking at this file in parallel.
        with contextlib.closing(
                mmap.mmap(ofd, 0, mmap.MAP_PRIVATE, mmap.PROT_READ, 0)) \
                as mapping:
            target.report_info("%s/%s: looking for `%s` in console %s:%s @%d-%d [%s]"
                               % (run_name, self.name, self.regex.pattern,
                                  target.fullid, self.console_name,
                                  search_offset, stat_info.st_size,
                                  of.name), dlevel = 4)
            match = self.regex.search(mapping[search_offset:])
            if match:
                output = mapping[search_offset
                                 : search_offset + match.end()]
                testcase.tls.buffers[context + 'search_offset'] = \
                    search_offset + match.end()
                # take care of printing a meaningful message here, as
                # this is one that many people rely on when doing
                # debugging on the serial line
                if self.name == self.regex.pattern:
                    # unnamed (we used the regex), that means they
                    # didn't care much for it, so dont' use it
                    _name = ""
                else:
                    _name = "/" + self.name
                target.report_info(
                    "%s%s: found '%s' at @%d-%d on console %s:%s [%s]"
                    % (run_name, _name, self.regex.pattern,
                       search_offset + match.start(),
                       search_offset + match.end(),
                       target.fullid, self.console_name, of.name),
                    attachments = { "console output": output },
                    dlevel = 1, alevel = 0)
                return {
                    "pattern": self.regex.pattern,
                    "from": search_offset,
                    "start": search_offset + match.start(),
                    "end": search_offset + match.end(),
                    "console output": output
                }

        return None

    def flush(self, testcase, run_name, buffers_poll, buffers,
              results):
        # we don't have to do anything, the collateral is already
        # generated in buffers['filename'], flushed and synced.
        pass


class console(tc.target_extension_c):
    """
    Extension to :py:class:`tcfl.tc.target_c` to run methods from the console
    management interface to TTBD targets.

    Use as:

    >>> target.console.read()
    >>> target.console.write()
    >>> target.console.setup()
    >>> target.console.list()

    """

    def __init__(self, target):
        if not 'test_target_console_mixin' in target.rt.get('interfaces', []):
            raise self.unneeded

    def read(self, console_id = None, offset = 0, fd = None):
        """
        Read data received on the target's console

        :param str console_id: (optional) console to read from
        :param int offset: (optional) offset to read from (defaults to zero)
        :param int fd: (optional) file descriptor to which to write
          the output (in which case, it returns the bytes read).
        :returns: data read (or if written to a file descriptor,
          amount of bytes read)
        """
        if console_id == None or console_id == "":
            console_id_name = "<default>"
        else:
            console_id_name = console_id
        self.target.report_info(
            "reading console '%s:%s' @%d" % (self.target.fullid,
                                             console_id_name, offset),
            dlevel = 1)
        if fd:
            r = self.target.rtb.rest_tb_target_console_read_to_fd(
                fd,
                self.target.rt, console_id, offset,
                ticket = self.target.ticket)
            ret = r
            l = r
        else:
            r = self.target.rtb.rest_tb_target_console_read(
                self.target.rt, console_id, offset,
                ticket = self.target.ticket)
            ret = r.text
            l = len(ret)
        self.target.report_info("read console '%s:%s' @%d %dB"
                                % (self.target.fullid, console_id_name,
                                   offset, l))
        return ret

    def size(self, console_id = None):
        """
        Return the amount of bytes so far read from the console

        :param str console_id: (optional) console to read from
        """
        return int(self.target.rtb.rest_tb_target_console_size(
            self.target.rt, console_id, ticket = self.target.ticket))

    def write(self, data, console_id = None):
        """
        Write data received to a console

        :param data: data to write
        :param str console_id: (optional) console to read from
        """
        if console_id == None or console_id == "":
            console_id_name = "<default>"
        else:
            console_id_name = console_id
        if len(data) > 30:
            data_report = data[:30] + "..."
        else:
            data_report = data
        data_report = filter(curses.ascii.isprint, data_report)
        self.target.report_info("writing to console '%s:%s'"
                                % (self.target.fullid, console_id_name),
                                dlevel = 1)
        self.target.rtb.rest_tb_target_console_write(
            self.target.rt, console_id, data, ticket = self.target.ticket)
        self.target.report_info("wrote '%s' to console '%s:%s'"
                                % (data_report, self.target.fullid,
                                   console_id_name))

    def setup(self, console_id = None, **kwargs):
        raise NotImplementedError

    def list(self):
        return self.target.rt.get('consoles', [])

    def expect_text(self, *args, **kwargs):
        """
        Return an object to expect a string or regex in this target's
        console.

        :param str text_or_regex: string to find; this can also be a
          regular expression.
        :param str console: (optional) name of the target's console from
          which we are to read. Defaults to the default console.

        (other parameters are the same as described in
        :class:`tcfl.tc.expectation_c`.)

        >>> target.console.expect_text(re.compile("DONE.*$"), timeout = 30)
        """
        return expect_text_on_console_c(*args, target = self.target, **kwargs)
