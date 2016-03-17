"""Remote Python Debugger (pdb wrapper)."""

__author__ = "Bertrand Janin <b@janin.com>"
__version__ = "0.1.6.shaleh"


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


class UnifiedObjects(object):
    """Present a unified interface to all objects provided.

    Treat the objects as one object, accessing attributes in the order
    the objects are given at initialization.
    """
    def __init__(self, *args):
        self._objs = args

    def __getattr__(self, name):
        for o in self._objs:
            if hasattr(o, name):
                return getattr(o, name)
        # this will raise the same AttributeError as if this method
        # was never called.
        return self.__getattribute__(name)


_GLOBAL_RPDB_SESSION = None


def new_session(*args, **kwargs):
    global _GLOBAL_RPDB_SESSION

    ephemeral = kwargs.pop("ephemeral")
    if ephemeral:
        return RpdbSession(*args, **kwargs)

    if _GLOBAL_RPDB_SESSION is None:
        _GLOBAL_RPDB_SESSION = RpdbSession(*args, **kwargs)

    return _GLOBAL_RPDB_SESSION


class RpdbSession(object):
    """Network session for rpdb."""
    def __init__(self, addr, port):
        self._addr = addr
        self._port = port
        self.skt = None

    def init(self):
        if self.skt:
            return True

        global OCCUPIED

        # Backup stdin and stdout before replacing them by the socket handle
        self.old_stdout = sys.stdout
        self.old_stdin = sys.stdin

        try:
            # Open a 'reusable' socket to let the debugging session reuse the port
            self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            self.skt.bind((self._addr, self._port))
            self.skt.listen(1)
        except socket.error:
            if OCCUPIED.is_claimed(self._port, sys.stdout):
                # rpdb is already on this port - good enough, let it go on:
                _logger.info("Recurrent rpdb invocation ignored")
                return False
            else:
                # Port occupied by something else.
                raise

        _logger.info("session created on %s:%d", *self.skt.getsockname())

        (clientsocket, _) = self.skt.accept()
        self.handle = clientsocket.makefile('rw')
        sys.stdout = sys.stdin = self.handle
        OCCUPIED.claim(self._port, self.handle)
        return True

    def shutdown(self):
        """Revert stdin and stdout, close the socket."""
        global OCCUPIED

        if self.old_stdout and self.old_stdin:
            sys.stdout = self.old_stdout
            sys.stdin = self.old_stdin
            self.old_stdout = None
            self.old_stdin = None

        try:
            if self.handle:
                try:
                    self.handle.close()
                except Exception as e:
                    _logger.exception(e)
                    _logger.debug("Failed to close handle")
                finally:
                    self.handle = None

                if self.skt:
                    try:
                        _logger.debug("session ending")
                        self.skt.shutdown(socket.SHUT_RDWR)
                        self.skt.close()
                    except Exception as e:
                        _logger.exception(e)
                        _logger.debug("Failed to close socket")
                    finally:
                        self.skt = None
        finally:
            _logger.info("Current port is: %d" % self._port)
            if self._port:
                OCCUPIED.unclaim(self._port)
                self._port = None


def finally_shutdown(session, method):
    def _wrapper(*args, **kwargs):
        try:
            _logger.info("in wrapper")
            return method(*args, **kwargs)
        finally:
            session.shutdown()
            # raise RuntimeError("Calling shutdown!!")
    return _wrapper


class Rpdb(object):
    """Stand-in for a PDB object enabling remote debugging.

    A socket is maintained by the session. All interaction is handled by the PDB instance.
    """
    def __init__(self, session):
        self._session = session
        self.pdb = pdb.Pdb(completekey='tab',
                           stdin=UnifiedObjects(self._session.handle, self._session.old_stdin),
                           stdout=UnifiedObjects(self._session.handle, self._session.old_stdout))
        self.pdb.do_continue = finally_shutdown(session, self.pdb.do_continue)
        self.pdb.do_quit = finally_shutdown(session, self.pdb.do_quit)
        self.pdb.do_EOF = finally_shutdown(session, self.pdb.do_EOF)

        _logger.debug("new PDB instance")

    def __getattr__(self, name):
        if hasattr(self.pdb, name):
            return getattr(self.pdb, name)
        return self.__getattribute__(name)


def set_trace(addr=DEFAULT_ADDR, port=DEFAULT_PORT, frame=None, maintain_session=True):
    """Wrapper function to keep the same import x; x.set_trace() interface.

    We catch all the possible exceptions from pdb and cleanup.
    """
    session = new_session(addr=addr, port=port, ephemeral=(not maintain_session))

    if not session.init():
        return

    debugger = Rpdb(session)
    try:
        debugger.set_trace(frame or sys._getframe().f_back)
    except Exception as e:
        _logger.exception(e)
        traceback.print_exc()
    # no code can go here or it will interfere with the debugger


def _trap_handler(addr, port, _, frame):
    """Trap handling callback function."""
    set_trace(addr, port, frame=frame)


def handle_trap(addr=DEFAULT_ADDR, port=DEFAULT_PORT):
    """Register rpdb as the SIGTRAP signal handler"""
    signal.signal(signal.SIGTRAP, partial(_trap_handler, addr, port))


def post_mortem(addr=DEFAULT_ADDR, port=DEFAULT_PORT, maintain_session=False):
    """Post mortem handler.

    Place this in a try/except handler.
    """
    session = new_session(addr=addr, port=port, ephemeral=(not maintain_session))
    if not session.init():
        return
    debugger = Rpdb(session)
    _, _, tb = sys.exc_info()
    traceback.print_exc(file=session.handle)
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
            _logger.info("releasing %d:%d" % (port, self.claims[port]))
            del self.claims[port]

# {port: sys.stdout} pairs to track recursive rpdb invocation on same port.
# This scheme doesn't interfere with recursive invocations on separate ports -
# useful, eg, for concurrently debugging separate threads.
OCCUPIED = OccupiedPorts()
