import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import sftp_client


class _FakeTransport:
    def __init__(self, active=True, host_key=b"host-key"):
        self._active = active
        self._host_key = host_key

    def is_active(self):
        return self._active

    def get_remote_server_key(self):
        class _Key:
            def __init__(self, raw):
                self._raw = raw

            def asbytes(self):
                return self._raw

        return _Key(self._host_key)


class _FakeClient:
    def __init__(self, active=True, host_key=b"host-key"):
        self.transport = _FakeTransport(active=active, host_key=host_key)

    def get_transport(self):
        return self.transport

    def close(self):
        pass


class _FakeSftp:
    def close(self):
        pass


class _Backend:
    def __init__(self):
        self.connect_calls = 0
        self.closed = 0
        self.raise_exc = None

    def connect(self, cfg, timeout_seconds):
        self.connect_calls += 1
        if self.raise_exc:
            raise self.raise_exc
        return _FakeClient(), _FakeSftp()

    def get_remote_host_key_fingerprint(self, client):
        return sftp_client.base64.b64encode(sftp_client.hashlib.sha256(b"host-key").digest()).decode("utf-8").rstrip("=")

    def is_active(self, client):
        return bool(client.get_transport().is_active())

    def close(self, client, sftp):
        self.closed += 1


class AuthBoom(Exception):
    pass


class SSHBoom(Exception):
    pass


class TestSftpClient(unittest.TestCase):
    def _cfg(self, **kw):
        data = {
            "owner": "u1",
            "mount_id": "m1",
            "host": "sftp.example.com",
            "port": 22,
            "username": "alice",
            "auth_mode": "password",
            "password": "pw",
            "protocol": "sftp",
            "expected_host_key": sftp_client.base64.b64encode(sftp_client.hashlib.sha256(b"host-key").digest()).decode("utf-8").rstrip("="),
        }
        data.update(kw)
        return sftp_client.SftpConnectionConfig(**data)

    def test_pool_reuses_connection_and_stats_observable(self):
        backend = _Backend()
        pool = sftp_client.SftpConnectionPool(backend=backend)
        with patch.object(sftp_client, "S") as settings:
            settings.filemgr_sftp_connect_timeout_seconds = 10
            settings.filemgr_sftp_pool_max_connections = 4
            settings.filemgr_sftp_host_key_policy = "strict"
            s1 = pool.acquire(self._cfg())
            pool.release(s1)
            s2 = pool.acquire(self._cfg())

        self.assertEqual(backend.connect_calls, 1)
        self.assertEqual(s1.key, s2.key)
        stats = pool.stats()
        self.assertEqual(stats["total_connects"], 1)
        self.assertEqual(stats["total_reuses"], 1)
        self.assertGreaterEqual(stats["active_sessions"], 1)

    def test_bounded_pool_evicts_idle_session(self):
        backend = _Backend()
        pool = sftp_client.SftpConnectionPool(backend=backend)
        with patch.object(sftp_client, "S") as settings:
            settings.filemgr_sftp_connect_timeout_seconds = 10
            settings.filemgr_sftp_pool_max_connections = 1
            settings.filemgr_sftp_host_key_policy = "strict"
            a = pool.acquire(self._cfg(mount_id="m1"))
            pool.release(a)
            pool.acquire(self._cfg(mount_id="m2"))

        stats = pool.stats()
        self.assertEqual(stats["pool_evictions"], 1)
        self.assertEqual(backend.closed, 1)

    def test_host_key_verification_failure_maps_to_stable_code(self):
        backend = _Backend()
        pool = sftp_client.SftpConnectionPool(backend=backend)
        with patch.object(sftp_client, "S") as settings:
            settings.filemgr_sftp_connect_timeout_seconds = 10
            settings.filemgr_sftp_pool_max_connections = 4
            settings.filemgr_sftp_host_key_policy = "strict"
            with self.assertRaises(HTTPException) as ctx:
                pool.acquire(self._cfg(expected_host_key="wrong"))

        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(ctx.exception.detail["code"], "host_key_mismatch")

    def test_connection_errors_are_categorized(self):
        backend = _Backend()
        pool = sftp_client.SftpConnectionPool(backend=backend)
        with patch.object(sftp_client, "S") as settings:
            settings.filemgr_sftp_connect_timeout_seconds = 10
            settings.filemgr_sftp_pool_max_connections = 4
            settings.filemgr_sftp_host_key_policy = "off"

            backend.raise_exc = TimeoutError("late")
            with self.assertRaises(HTTPException) as tctx:
                pool.acquire(self._cfg(expected_host_key=None))
            self.assertEqual(tctx.exception.detail["code"], "network_timeout")

            backend.raise_exc = AuthBoom("auth denied")
            with self.assertRaises(HTTPException) as actx:
                pool.acquire(self._cfg(expected_host_key=None))
            self.assertEqual(actx.exception.detail["code"], "auth_failed")

            backend.raise_exc = SSHBoom("ssh problem")
            with self.assertRaises(HTTPException) as sctx:
                pool.acquire(self._cfg(expected_host_key=None))
            self.assertEqual(sctx.exception.detail["code"], "protocol_error")

        stats = pool.stats()
        self.assertEqual(stats["failed_connects"], 3)

    def test_destination_policy_checked_at_connection_time(self):
        backend = _Backend()
        pool = sftp_client.SftpConnectionPool(backend=backend)
        with (
            patch.object(sftp_client, "S") as settings,
            patch.object(sftp_client, "enforce_sftp_destination_policy", side_effect=HTTPException(status_code=403, detail={"code": "sftp_destination_not_allowed", "message": "blocked"})) as enforce,
        ):
            settings.filemgr_sftp_connect_timeout_seconds = 10
            settings.filemgr_sftp_pool_max_connections = 4
            settings.filemgr_sftp_host_key_policy = "strict"
            with self.assertRaises(HTTPException) as ctx:
                pool.acquire(self._cfg())

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "sftp_destination_not_allowed")
        enforce.assert_called_once()
        self.assertEqual(backend.connect_calls, 0)

    def test_local_mock_backend_selected_via_settings_and_supports_file_ops(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sftp_client, "S") as settings:
                settings.filemgr_sftp_backend = "mock"
                settings.filemgr_sftp_mock_root_dir = tmp
                settings.filemgr_sftp_connect_timeout_seconds = 10
                settings.filemgr_sftp_pool_max_connections = 4
                settings.filemgr_sftp_host_key_policy = "off"
                pool = sftp_client.SftpConnectionPool()
                self.assertEqual(pool._backend.__class__.__name__, "_LocalMockBackend")

                for protocol in ("sftp", "scp", "ftp"):
                    sess = pool.acquire(self._cfg(protocol=protocol, expected_host_key=None))
                    try:
                        sess.sftp.mkdir(f"/{protocol}")
                        with sess.sftp.open(f"/{protocol}/readme.txt", "wb") as fp:
                            fp.write(f"hello-{protocol}".encode("utf-8"))
                        attrs = sess.sftp.listdir_attr(f"/{protocol}")
                        self.assertEqual([a.filename for a in attrs], ["readme.txt"])
                        with sess.sftp.open(f"/{protocol}/readme.txt", "rb") as fp:
                            self.assertEqual(fp.read(), f"hello-{protocol}".encode("utf-8"))
                    finally:
                        pool.release(sess)

    def test_scp_protocol_uses_standard_backend_flow(self):
        backend = _Backend()
        pool = sftp_client.SftpConnectionPool(backend=backend)
        with patch.object(sftp_client, "S") as settings:
            settings.filemgr_sftp_connect_timeout_seconds = 10
            settings.filemgr_sftp_pool_max_connections = 4
            settings.filemgr_sftp_host_key_policy = "strict"
            sess = pool.acquire(self._cfg(protocol="scp"))
            pool.release(sess)
        self.assertEqual(backend.connect_calls, 1)

    def test_ftp_protocol_uses_ftp_backend(self):
        backend = _Backend()
        pool = sftp_client.SftpConnectionPool(backend=backend)

        class _FtpLike:
            def voidcmd(self, _cmd):
                return "200"
            def quit(self):
                return None

        class _Shim:
            def close(self):
                return None

        with (
            patch.object(sftp_client, "S") as settings,
            patch.object(sftp_client._FtpBackend, "connect", return_value=(_FtpLike(), _Shim())) as ftp_connect,
        ):
            settings.filemgr_sftp_connect_timeout_seconds = 10
            settings.filemgr_sftp_pool_max_connections = 4
            settings.filemgr_sftp_host_key_policy = "strict"
            sess = pool.acquire(self._cfg(protocol="ftp", expected_host_key=None))
            pool.release(sess)

        ftp_connect.assert_called_once()
        self.assertEqual(backend.connect_calls, 0)


if __name__ == "__main__":
    unittest.main()
