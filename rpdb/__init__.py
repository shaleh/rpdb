"""Remote Python Debugger (pdb wrapper)."""

__author__ = "Bertrand Janin <b@janin.com>"
__version__ = "0.1.6.shaleh"


from functools import partial
import pdb
import signal
import socket
import sys
import threading
import traceback

DEFAULT_ADDR = "127.0.0.1"
DEFAULT_PORT = 4444


class FileObjectWrapper(object):
    def __init__(self, fileobject, stdio):
        self._obj = fileobject
        self._io = stdio

    def __getattr__(self, attr):
        if hasattr(self._obj, attr):
            return getattr(self._obj, attr)
        elif hasattr(self._io, attr):
            return getattr(self._io, attr)
        else:
            # this will raise the same AttributeError as if this method
            # was never called.
            return self.__getattribute__(attr)


class RpdbSession(object):

    def __init__(self, addr, port):
        """Initialize the socket."""

        # Backup stdin and stdout before replacing them by the socket handle
        self.old_stdout = sys.stdout
        self.old_stdin = sys.stdin
        self.port = port

        # Open a 'reusable' socket to let the webapp reload on the same port
        self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.skt.bind((addr, port))
        self.skt.listen(1)

        # Writes to stdout are forbidden in mod_wsgi environments
        try:
            sys.stderr.write("pdb is running on %s:%d\n"
                             % self.skt.getsockname())
        except IOError:
            pass

        (clientsocket, address) = self.skt.accept()
        self.handle = clientsocket.makefile('rw')
        sys.stdout = sys.stdin = self.handle
        OCCUPIED.claim(port, self.handle)

    def shutdown(self):
        """Revert stdin and stdout, close the socket."""
        sys.stdout = self.old_stdout
        sys.stdin = self.old_stdin
        OCCUPIED.unclaim(self.port)
        self.skt.close()


class Rpdb(object):
    def __init__(self, session):
        self._session = session

        self.pdb = pdb.Pdb(completekey='tab',
                           stdin=FileObjectWrapper(self._session.handle, self._session.old_stdin),
                           stdout=FileObjectWrapper(self._session.handle, self._session.old_stdout))

    def shutdown(self):
        self._session.shutdown()
        self._session = None

    def do_continue(self, arg):
        """Clean-up and do underlying continue."""
        # left here because maybe I want to have a toggle for quitting...
        return self.pdb.do_continue(self, arg)

    do_c = do_cont = do_continue

    def do_quit(self, arg):
        """Clean-up and do underlying quit."""
        try:
            return self.pdb.do_quit(self, arg)
        finally:
            self.shutdown()

    do_q = do_exit = do_quit

    def do_EOF(self, arg):
        """Clean-up and do underlying EOF."""
        try:
            return self.pdb.do_EOF(self, arg)
        finally:
            self.shutdown()

    def __getattr__(self, name):
        if not hasattr(self.pdb, name):
            return self.__getattribute__(name)
        return getattr(self.pdb, name)


_GLOBAL_RPDB_SESSION = None


def set_trace(addr=DEFAULT_ADDR, port=DEFAULT_PORT, frame=None, maintain_session=True):
    """Wrapper function to keep the same import x; x.set_trace() interface.

    We catch all the possible exceptions from pdb and cleanup.

    """
    global _GLOBAL_RPDB_SESSION
    try:
        if maintain_session:
            if _GLOBAL_RPDB_SESSION is None:
                _GLOBAL_RPDB_SESSION = RpdbSession(addr=addr, port=port)
            session = _GLOBAL_RPDB_SESSION
        else:
            session = RpdbSession(addr=addr, port=port)
        debugger = Rpdb(session)
    except socket.error:
        if OCCUPIED.is_claimed(port, sys.stdout):
            # rpdb is already on this port - good enough, let it go on:
            sys.stdout.write("(Recurrent rpdb invocation ignored)\n")
            return
        else:
            # Port occupied by something else.
            raise
    try:
        debugger.set_trace(frame or sys._getframe().f_back)
    except Exception:
        traceback.print_exc()


def _trap_handler(addr, port, signum, frame):
    set_trace(addr, port, frame=frame)


def handle_trap(addr=DEFAULT_ADDR, port=DEFAULT_PORT):
    """Register rpdb as the SIGTRAP signal handler"""
    signal.signal(signal.SIGTRAP, partial(_trap_handler, addr, port))


def post_mortem(addr=DEFAULT_ADDR, port=DEFAULT_PORT):
    session = RpdbSession(addr=addr, port=port)
    debugger = Rpdb(session)
    type, value, tb = sys.exc_info()
    traceback.print_exc()
    debugger.reset()
    debugger.interaction(None, tb)


class OccupiedPorts(object):
    """Maintain rpdb port versus stdin/out file handles.

    Provides the means to determine whether or not a collision binding to a
    particular port is with an already operating rpdb session.

    Determination is according to whether a file handle is equal to what is
    registered against the specified port.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.claims = {}

    def claim(self, port, handle):
        with self.lock:
            self.claims[port] = id(handle)

    def is_claimed(self, port, handle):
        with self.lock:
            return (self.claims.get(port) == id(handle))

    def unclaim(self, port):
        with self.lock:
            del self.claims[port]

# {port: sys.stdout} pairs to track recursive rpdb invocation on same port.
# This scheme doesn't interfere with recursive invocations on separate ports -
# useful, eg, for concurrently debugging separate threads.
OCCUPIED = OccupiedPorts()
