"""Remote Python Debugger (pdb wrapper)."""

__author__ = "Bertrand Janin <b@janin.com>"
__version__ = "0.1.6.shaleh"

__all__ = ('Rpdb', 'handle_trap', 'post_mortem', 'set_trace')

from functools import partial
import logging
import pdb
import signal
import socket
import sys
import threading
import traceback

DEFAULT_ADDR = "127.0.0.1"
DEFAULT_PORT = 4444

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


class FileObjectWrapper(object):
    def __init__(self, obj, io):
        self._obj = obj
        self._io = io

    def __getattr__(self, attr):
        if hasattr(self._obj, attr):
            return getattr(self._obj, attr)
        if hasattr(self._io, attr):
            return getattr(self._io, attr)

        # this mimics standard Python behavior
        return self.__getattribute__(attr)


def finally_shutdown(owner, method):
    """Wrapper to ensure clean-up happens after `method` is called."""
    def _wrapper(*args, **kwargs):
        """Clean-up after calling method."""
        try:
            return method(*args, **kwargs)
        finally:
            owner.shutdown()
    return _wrapper


class RemoteSession(object):
    def __init__(self, addr, port, long_living=False):
        self.port = port
        self.handle = None
        self.long_living = long_living

        # Open a 'reusable' socket prevent errors when the socket is reopened
        # before the last session has fully timed out.
        self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.skt.bind((addr, port))
        self.skt.listen(1)

        _logger.info("remote session is running on %s:%d" % self.skt.getsockname())

    def begin(self):
        if OCCUPIED.is_claimed(self.port, self.handle):
            return  # already active

        (clientsocket, _) = self.skt.accept()
        self.handle = clientsocket.makefile('rw')
        # Backup stdin and stdout before replacing them by the socket handle
        self.old_stdout = sys.stdout
        self.old_stdin = sys.stdin
        self.stdout = FileObjectWrapper(self.handle, self.old_stdout)
        self.stdin = FileObjectWrapper(self.handle, self.old_stdin)
        sys.stdout = self.stdout
        sys.stdin = self.stdin

        OCCUPIED.claim(self.port, self.handle)

    def shutdown(self):
        _logger.info("remote session completed: %d:%d" % (port, self.handle))
        sys.stdout = self.old_stdout
        sys.stdin = self.old_stdin
        self.handle.close()
        OCCUPIED.unclaim(self.port)
        self.skt.shutdown(socket.SHUT_RDWR)
        self.skt.close()


class Rpdb(object):
    """Wrap a Pdb object with a remote session."""

    _long_lived_session = None

    @classmethod
    def new_session(cls, addr=DEFAULT_ADDR, port=DEFAULT_PORT, long_living=False):
        if long_living:
            if not cls._long_lived_session:
                cls._long_lived_session = RemoteSession(addr=addr, port=port, long_living=long_living)
            return cls._long_lived_session
        elif cls._long_lived_session.skt is not None:
            _logger.debug("pdb session already active, reusing it.")
            return cls._long_lived_session
        return RemoteSession(addr=addr, port=port)

    def __init__(self, session):
        self._session = session
        self._pdb = None

    def start_debugger(self):
        """Accept external connections and run Pdb."""
        self._session.begin()

        self._pdb = pdb.Pdb(completekey='tab',
                            stdin=self._session.stdin,
                            stdout=self._session.stdout)
        # wrap the methods that need extra logic
        for method in ('do_continue', 'do_c', 'do_cont',
                       'do_quit', 'do_exit', 'do_q',
                       'do_EOF'):
            setattr(self._pdb, method, finally_shutdown(self, getattr(self._pdb, method)))

        _logger.debug("pdb client connected")

    def shutdown(self):
        """Revert stdin and stdout, close the socket."""
        if not self._session.long_living:
            self._session.shutdown()

    def __getattr__(self, name):
        """Pass on requests to the Pdb object."""
        if hasattr(self._pdb, name):
            return getattr(self._pdb, name)
        return self.__getattribute__(name)


def set_trace(addr=DEFAULT_ADDR, port=DEFAULT_PORT, frame=None, long_living=False):
    """Wrapper function to keep the same import x; x.set_trace() interface.

    We catch all the possible exceptions from pdb and cleanup.
    """
    try:
        session = Rpdb.new_session(addr=addr, port=port, long_living=long_living)
        debugger = Rpdb(session)
        debugger.start_debugger()
    except socket.error:
        if OCCUPIED.is_claimed(port, sys.stdout):
            # rpdb is already on this port - good enough, let it go on:
            _logger.info("Recurrent rpdb invocation ignored")
            return
        else:
            # Port occupied by something else.
            raise

    try:
        debugger.set_trace(frame or sys._getframe().f_back)
    except Exception:
        traceback.print_exc()
    # no code can go here or it will interfere with the debugger


def _trap_handler(addr, port, _, frame):
    """Trap handling callback function."""
    set_trace(addr, port, frame=frame)


def handle_trap(addr=DEFAULT_ADDR, port=DEFAULT_PORT):
    """Register rpdb as the SIGTRAP signal handler"""
    signal.signal(signal.SIGTRAP, partial(_trap_handler, addr, port))


def post_mortem(addr=DEFAULT_ADDR, port=DEFAULT_PORT, long_living=False):
    """Post mortem handler.

    Place this in a try/except handler.
    """
    # capture the existing exception before creating the debugger in case
    # another exception is thrown
    type, value, tb = sys.exc_info()
    traceback.print_exc()

    session = Rpdb.new_session(addr=addr, port=port, long_living=False)
    debugger = Rpdb(session)
    debugger.start_debugger()
    debugger.reset()
    debugger.interaction(None, tb)


class OccupiedPorts(object):
    """Maintain rpdb port to file handle mappings.

    Provides the means to determine whether or not a collision binding to a
    particular port is with an already operating rpdb session.

    Determination is according to whether a file handle is equal to what is
    registered against the specified port.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.claims = {}

    def claim(self, port, handle):
        """Claim a (port, handle) pair."""
        with self.lock:
            self.claims[port] = id(handle)

    def is_claimed(self, port, handle):
        """Is (port, handle) claimed?"""
        with self.lock:
            return self.claims.get(port) == id(handle)

    def unclaim(self, port):
        """Release a (port, handle) pair."""
        with self.lock:
            del self.claims[port]

# {port: sys.stdout} pairs to track recursive rpdb invocation on same port.
# This scheme doesn't interfere with recursive invocations on separate ports -
# useful, eg, for concurrently debugging separate threads.
OCCUPIED = OccupiedPorts()
