import io
import os
import posixpath
import time
import warnings
import paramiko

try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning, module='paramiko')
except Exception:
    pass


def _load_private_key_from_text(key_text: str):
    text = (key_text or '').strip()
    if not text:
        return None
    stream = io.StringIO(text)
    loaders = [
        paramiko.Ed25519Key.from_private_key,
        paramiko.RSAKey.from_private_key,
        paramiko.ECDSAKey.from_private_key,
    ]
    for loader in loaders:
        stream.seek(0)
        try:
            return loader(stream)
        except Exception:
            continue
    return None


class SSHRunner:
    def __init__(self, host: str, username: str, password: str = '', port: int = 22, timeout: int = 15, auth_mode: str = '', private_key: str = ''):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.client = None
        self.auth_mode = auth_mode
        self.private_key = private_key

    def __enter__(self):
        effective_mode = (self.auth_mode or '').strip() or 'auto'
        key_text = self.private_key
        if not key_text:
            try:
                from core.settings import load_settings
                settings = load_settings()
                effective_mode = (self.auth_mode or settings.get('ssh_auth_mode') or 'auto').strip() or 'auto'
                key_text = settings.get('ssh_private_key', '') or ''
            except Exception:
                pass
        pkey = _load_private_key_from_text(key_text)

        last_error = None
        retries = 2
        for attempt in range(1, retries + 1):
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                if pkey and effective_mode in {'key', 'auto'}:
                    try:
                        self.client.connect(
                            hostname=self.host,
                            port=self.port,
                            username=self.username,
                            pkey=pkey,
                            timeout=self.timeout,
                            banner_timeout=self.timeout,
                            auth_timeout=self.timeout,
                            allow_agent=False,
                            look_for_keys=False,
                        )
                        return self
                    except Exception as key_exc:
                        last_error = key_exc
                        if effective_mode == 'key':
                            raise

                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                return self
            except Exception as exc:
                last_error = exc
                text = str(exc).lower()
                fatal = (
                    ('authentication failed' in text)
                    or ('private key file is encrypted' in text)
                    or ('not a valid' in text and 'key' in text)
                )
                try:
                    self.client.close()
                except Exception:
                    pass
                if fatal or attempt >= retries:
                    raise
                time.sleep(0.6)

        if last_error:
            raise last_error
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.client:
            self.client.close()

    def run(self, command: str, timeout: int = 1200):
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        code = stdout.channel.recv_exit_status()
        return code, out, err

    def upload(self, local_path: str, remote_path: str):
        sftp = self.client.open_sftp()
        remote_dir = posixpath.dirname(remote_path)
        self.run(f"mkdir -p '{remote_dir}'")
        sftp.put(local_path, remote_path)
        sftp.close()

    def chmod(self, remote_path: str, mode: str = '755'):
        self.run(f"chmod {mode} '{remote_path}'")
