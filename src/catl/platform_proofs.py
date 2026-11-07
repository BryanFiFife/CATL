"""Read-only platform isolation evidence collectors; fail closed on unsupported hosts.

These are deployment gates, NOT launchers or sandboxes. A token report alone
cannot prove filesystem/network containment of a separate application.
"""
from __future__ import annotations
import ctypes
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any


class PlatformProofError(PermissionError):
    pass


def windows_current_token_proof() -> dict[str, Any]:
    """Windows *current-process* AppContainer/restricted-token kernel evidence.

    No claim is made about a different PID, a named pipe ACL or network policy.
    """
    if sys.platform != "win32":
        raise PlatformProofError("windows_kernel_required")
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    TOKEN_QUERY = 0x0008
    TOKEN_IS_APP_CONTAINER = 29
    TOKEN_HAS_RESTRICTIONS = 21
    handle = wintypes.HANDLE()
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(handle)):
        raise PlatformProofError("token_query_failed")
    try:
        def read_flag(token_class: int) -> bool:
            value = wintypes.DWORD()
            needed = wintypes.DWORD()
            if not advapi.GetTokenInformation(handle, token_class, ctypes.byref(value),
                                              ctypes.sizeof(value), ctypes.byref(needed)):
                raise PlatformProofError("token_info_query_failed")
            return value.value != 0
        is_container = read_flag(TOKEN_IS_APP_CONTAINER)
        has_restrictions = read_flag(TOKEN_HAS_RESTRICTIONS)
        if not is_container or not has_restrictions:
            raise PlatformProofError("process_not_restricted_appcontainer")
        return {"platform": "win32", "appcontainer": True, "has_restrictions": True,
                "named_pipe_acl_verified": False, "network_confinement_verified": False}
    finally:
        kernel.CloseHandle(handle)


def macos_peer_uid(conn: socket.socket, expected_uid: int) -> dict[str, int]:
    """Get kernel-supplied effective identity from an already accepted AF_UNIX socket."""
    if sys.platform != "darwin":
        raise PlatformProofError("macos_kernel_required")
    if conn.family != socket.AF_UNIX or conn.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
        raise PlatformProofError("not_unix_stream_socket")
    if type(expected_uid) is not int or expected_uid < 1:
        raise PlatformProofError("invalid_expected_uid")
    try:
        uid, gid = conn.getpeereid()
    except (AttributeError, OSError) as exc:
        raise PlatformProofError("kernel_peer_credentials_unavailable") from exc
    if uid != expected_uid:
        raise PlatformProofError("macos_peer_uid_mismatch")
    return {"uid": uid, "gid": gid}


def protected_unix_socket_path(path: Path, *, expected_owner: int) -> None:
    """Refuse symlinked/mutable endpoints and ancestor directories.

    Caller must separately check its accepted peer with getpeereid/SO_PEERCRED.
    """
    path = Path(path)
    if not path.is_absolute() or type(expected_owner) is not int or expected_owner < 1:
        raise PlatformProofError("socket_path_invalid")
    parts = [path, *path.parents]
    for node in parts:
        st = os.lstat(node)
        if stat.S_ISLNK(st.st_mode):
            raise PlatformProofError("socket_ancestor_symlink")
        if node != path and not stat.S_ISDIR(st.st_mode):
            raise PlatformProofError("socket_ancestor_not_directory")
        if node != path and st.st_uid not in (expected_owner, 0):
            raise PlatformProofError("socket_ancestor_untrusted_owner")
        if node not in (Path('/'),Path('/tmp'),Path('/var'),Path('/private'),Path('/private/tmp')):
            if st.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
                raise PlatformProofError("socket_ancestor_writable")
    st = os.lstat(path)
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != expected_owner or st.st_mode & stat.S_IWOTH:
        raise PlatformProofError("socket_owner_or_mode_invalid")


def linux_self_confinement_proof(*, proc_status: str | None = None,
                                 cgroup_memory: str | None = None,
                                 cgroup_pids: str | None = None,
                                 cgroup_root: Path = Path("/sys/fs/cgroup")) -> dict[str, Any]:
    """Kernel inspection of the *calling process*, never an arbitrary user PID.

    Inputs facilitate deterministic tests; production callers should omit them.
    This cannot prove network egress or a systemd unit was installed properly.
    """
    if sys.platform != "linux":
        raise PlatformProofError("linux_kernel_required")
    status = proc_status if proc_status is not None else Path('/proc/self/status').read_text()
    pairs = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    try:
        uid = [int(x) for x in pairs['Uid'].split()]
        cap_eff = int(pairs['CapEff'].strip(), 16)
        cap_bnd = int(pairs['CapBnd'].strip(), 16)
        seccomp = int(pairs['Seccomp'].strip())
        no_new_privs = int(pairs['NoNewPrivs'].strip())
    except (ValueError, KeyError, IndexError) as exc:
        raise PlatformProofError("kernel_status_incomplete") from exc
    if any(x == 0 for x in uid) or cap_eff or cap_bnd or seccomp != 2 or no_new_privs != 1:
        raise PlatformProofError("linux_process_not_strictly_confined")
    # On real hosts derive the current process cgroup from the kernel, not a
    # caller-supplied path. Synthetic inputs are accepted for offline tests.
    if cgroup_memory is None or cgroup_pids is None:
        groups=Path('/proc/self/cgroup').read_text().splitlines()
        relative=[line.split('::',1)[1] for line in groups if line.startswith('0::')]
        if len(relative)!=1 or '..' in Path(relative[0]).parts:
            raise PlatformProofError('current_cgroup_v2_unavailable')
        group=cgroup_root/relative[0].lstrip('/')
        if group.is_symlink() or not group.is_dir():
            raise PlatformProofError('cgroup_path_invalid')
        if cgroup_memory is None:
            cgroup_memory=(group/'memory.max').read_text()
        if cgroup_pids is None:
            cgroup_pids=(group/'pids.max').read_text()
    try:
        memory = int(cgroup_memory.strip())
        pids = int(cgroup_pids.strip())
    except ValueError as exc:
        raise PlatformProofError("cgroup_limits_unbounded") from exc
    if memory <= 0 or memory > 4 * 1024**3 or pids <= 0 or pids > 128:
        raise PlatformProofError("cgroup_limits_unsafe")
    return {"platform": "linux", "non_root_uid": uid[1], "cap_eff": cap_eff,
            "cap_bnd": cap_bnd, "no_new_privs": 1, "seccomp": 2,
            "memory_limit": memory, "pids_limit": pids,
            "network_egress_verified": False, "live_hermes_verified": False}


def windows_named_pipe_acl_proof(pipe_name:str, *, exact_allowed_sids:set[str]) -> dict[str, Any]:
    """Inspect a named pipe DACL, rejecting unreviewed allow principals.

    This does NOT launch a restricted-token process. Requires pywin32 and
    verification on an actual Windows host. Call before exposing the pipe.
    """
    if sys.platform!='win32':raise PlatformProofError('windows_kernel_required')
    if (not isinstance(pipe_name,str) or not pipe_name.startswith('\\\\.\\pipe\\CATL-')
            or len(pipe_name)>150 or not exact_allowed_sids or
            any(not isinstance(s,str) or not s.startswith('S-1-') for s in exact_allowed_sids)):
        raise PlatformProofError('pipe_acl_parameters_invalid')
    try:
        import win32security
        rights=win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION
        sd=win32security.GetNamedSecurityInfo(pipe_name,win32security.SE_FILE_OBJECT,rights)
        dacl=sd.GetSecurityDescriptorDacl()
        if dacl is None:raise PlatformProofError('pipe_null_dacl')
        seen=set()
        for idx in range(dacl.GetAceCount()):
            header,access,sid = dacl.GetAce(idx)
            sid_text=win32security.ConvertSidToStringSid(sid)
            if header[0] not in (win32security.ACCESS_ALLOWED_ACE_TYPE,
                                 win32security.ACCESS_DENIED_ACE_TYPE):
                raise PlatformProofError('pipe_unreviewed_ace_type')
            if header[1] & win32security.INHERITED_ACE:
                raise PlatformProofError('pipe_mutable_inherited_acl')
            if header[0] == win32security.ACCESS_ALLOWED_ACE_TYPE:
                if sid_text not in exact_allowed_sids:
                    raise PlatformProofError('pipe_broad_or_unknown_ace')
                seen.add(sid_text)
        if not exact_allowed_sids.issubset(seen):
            raise PlatformProofError('pipe_required_aces_missing')
    except ImportError as exc:
        raise PlatformProofError('windows_acl_library_missing') from exc
    return {'named_pipe_acl_verified':True,'allowed_sids':sorted(exact_allowed_sids),
            'restricted_token_launcher_verified':False}
