"""Bounded static privacy inspection; executable and Python code never run.

Only primitive marshal objects in PYZ tables are decoded. Marshaled code stays
opaque and is scanned as bytes, so foreign Python bytecode is also supported.
"""
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import zipfile
import zlib


MAX_FILE_BYTES = 256 * 1024 * 1024
# Electron's signed upstream executable is larger than 128 MiB. Keep each
# expanded member bounded by the same 256 MiB limit used for standalone files.
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 1536 * 1024 * 1024
MAX_MEMBERS = 30000
MAX_DEPTH = 8
MAX_RATIO = 250
MAX_TOC_BYTES = 8 * 1024 * 1024
PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
CARCHIVE_MAGIC = b'MEI\014\013\012\013\016'
COOKIE = struct.Struct('!8sIIII64s')
TOC_ENTRY = struct.Struct('!IIIIBc')

# Pristine upstream Electron 45.0.0 linux-x64 and win32-x64 executables, verified
# against the official ZIP checksums shipped in the pinned electron npm package.
# They embed public build paths. ONLY exact immutable bytes may skip personal-path
# heuristic; explicit forbidden values, private keys and tokens still fail.
# Updates must verify the official archive checksum and record the new hash.
UPSTREAM_RUNTIME_SHA256 = frozenset({
    'b36c3ce9b423098a7854f4912f730b0654b41ae183818f887b8f1cd0a90725eb',
    '8e84549b05d27d444da2957653200d1e0ac287eff0fc5722b92835b9e0821a59',
})


class PrivacyError(Exception):
    def __init__(self, category):
        self.category = category
        super().__init__('release privacy check failed [' + category + ']')


class ScanPolicy:
    max_file_bytes = MAX_FILE_BYTES
    _key = re.compile(
        rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'
        rb'\s+[A-Za-z0-9+/=\r\n\t ]{32,}?\s*'
        rb'-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')
    _tokens = tuple((prefixes, re.compile(pattern)) for prefixes, pattern in (
        ((b'ghp_', b'gho_', b'ghu_', b'ghs_', b'ghr_'),
         rb'(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])'),
        ((b'github_pat_',), rb'(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{60,255}(?![A-Za-z0-9_])'),
        ((b'xoxb-', b'xoxa-', b'xoxp-', b'xoxr-', b'xoxs-'),
         rb'(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{24,255}'),
        ((b'sk_live_', b'sk_proj_'), rb'(?<![A-Za-z0-9])sk_(?:live|proj)_[A-Za-z0-9_-]{24,255}'),
        ((b'sk-proj-',), rb'(?<![A-Za-z0-9])sk-proj-[A-Za-z0-9_-]{40,255}'),
    ))
    _unix_path = re.compile(rb'/(?:Users|home)/([^/\r\n\t\\\x00"\x27`<>{}]{1,80})[/\\]')
    _windows_path = re.compile(rb'[A-Za-z]:[\\/]+Users[\\/]+([^/\r\n\t\\\x00"\x27`<>{}]{1,80})[\\/]', re.I)
    _public_path_users = frozenset((b'user', b'username', b'example', b'alice', b'bob',
                                    b'test', b'runner', b'agent', b'public', b'default',
                                    b'all users', b'build', b'containeruser'))
    _windows_build_users = frozenset((b'runneradmin',))
    _runtime = frozenset(('chat.db', 'private_key.pem', 'public_key.pem', '.gitconfig',
                          'client.json', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
                          'known_hosts', 'authorized_keys', 'server.key', 'client.key'))

    def __init__(self, forbidden=()):
        self.forbidden = tuple(value.encode('utf-8') for value in forbidden)

    @classmethod
    def from_environment(cls):
        encoded = os.environ.get('PRIVACY_FORBIDDEN_VALUES_JSON', '').strip() or '[]'
        if len(encoded) > 128 * 1024:
            raise PrivacyError('privacy-policy-config')
        try:
            values = json.loads(encoded)
        except (TypeError, ValueError):
            raise PrivacyError('privacy-policy-config') from None
        if (not isinstance(values, list) or len(values) > 100
                or any(not isinstance(x, str) or not 3 <= len(x) <= 1024 for x in values)):
            raise PrivacyError('privacy-policy-config')
        return cls(values)

    def filename(self, name):
        normalized = name.replace('\\', '/')
        parts = PurePosixPath(normalized).parts
        if (not name or '\0' in name or normalized.startswith('/')
                or re.match(r'^[A-Za-z]:', normalized) or '..' in parts):
            raise PrivacyError('unsafe-entry-name')
        basename = parts[-1].lower()
        if (any(x.lower() in ('.git', '.ssh', '.aws') for x in parts)
                or basename in self._runtime
                or basename.endswith(('.db.key', '.log', '.sqlite', '.sqlite3', '.key'))
                or (basename == '.env' or basename.startswith('.env.'))
                and not basename.endswith(('.example', '.sample', '.template'))):
            raise PrivacyError('runtime-file')
        self.content(name.encode('utf-8', errors='surrogateescape'))

    def content(self, data):
        if self.forbidden:
            lowered = data.lower()
            for value in self.forbidden:
                if value.lower() in lowered:
                    raise PrivacyError('private-value')
                text = value.decode('utf-8')
                if text.encode('utf-16le') in data or text.encode('utf-16be') in data:
                    raise PrivacyError('private-value')
        if b'-----BEGIN ' in data and self._key.search(data):
            raise PrivacyError('private-key')
        if any(any(prefix in data for prefix in prefixes) and pattern.search(data)
               for prefixes, pattern in self._tokens):
            raise PrivacyError('credential-token')
        path_patterns = []
        if b'/home/' in data or b'/Users/' in data:
            path_patterns.append(self._unix_path)
        if b'users' in data.lower():
            path_patterns.append(self._windows_path)
        for pattern in path_patterns:
            allowed = self._public_path_users
            if pattern is self._windows_path:
                allowed = allowed | self._windows_build_users
            if any(match[1].lower() not in allowed for match in pattern.finditer(data)):
                if hashlib.sha256(data).hexdigest() not in UPSTREAM_RUNTIME_SHA256:
                    raise PrivacyError('personal-path')

    def source(self, data, name):
        self.content(data)
        if data.startswith(PNG_MAGIC) or name.lower().endswith('.png'):
            check_png(data)


def check_png(data):
    if not data.startswith(PNG_MAGIC):
        raise PrivacyError('png-format')
    position = len(PNG_MAGIC)
    seen_header = False
    while position + 12 <= len(data):
        size = struct.unpack_from('!I', data, position)[0]
        kind = data[position + 4:position + 8]
        end = position + 12 + size
        if end > len(data) or size > MAX_MEMBER_BYTES:
            raise PrivacyError('png-format')
        payload = data[position + 8:position + 8 + size]
        checksum = struct.unpack_from('!I', data, end - 4)[0]
        if zlib.crc32(kind + payload) & 0xffffffff != checksum:
            raise PrivacyError('png-format')
        if kind in (b'tEXt', b'zTXt', b'iTXt', b'eXIf', b'iCCP'):
            raise PrivacyError('png-private-metadata')
        if not seen_header:
            if kind != b'IHDR' or size != 13:
                raise PrivacyError('png-format')
            seen_header = True
        if kind == b'IEND':
            if size != 0 or end != len(data):
                raise PrivacyError('png-format')
            return
        position = end
    raise PrivacyError('png-format')


class _MarshalTOC:
    """Decode a bounded primitive-only subset of Python's marshal format."""
    def __init__(self, data):
        if len(data) > MAX_TOC_BYTES:
            raise PrivacyError('archive-limit')
        self.data, self.position, self.refs, self.nodes = data, 0, [], 0

    def read(self, size):
        if size < 0 or self.position + size > len(self.data):
            raise PrivacyError('pyz-format')
        value = self.data[self.position:self.position + size]
        self.position += size
        return value

    def number(self):
        return struct.unpack('<i', self.read(4))[0]

    def value(self, depth=0):
        self.nodes += 1
        if depth > 32 or self.nodes > MAX_MEMBERS * 12:
            raise PrivacyError('archive-limit')
        kind = self.read(1)[0]
        reference = bool(kind & 0x80)
        kind &= 0x7f
        slot = len(self.refs)
        if reference:
            self.refs.append(None)
        if kind == ord('r'):
            index = self.number()
            if reference or not 0 <= index < len(self.refs):
                raise PrivacyError('pyz-format')
            return self.refs[index]
        if kind == ord('N'):
            result = None
        elif kind == ord('i'):
            result = self.number()
        elif kind == ord('I'):
            result = struct.unpack('<q', self.read(8))[0]
        elif kind == ord('l'):
            count = self.number()
            if abs(count) > 8:
                raise PrivacyError('archive-limit')
            result = 0
            for index in range(abs(count)):
                digit = struct.unpack('<H', self.read(2))[0]
                if digit >= 32768:
                    raise PrivacyError('pyz-format')
                result |= digit << (15 * index)
            result *= -1 if count < 0 else 1
        elif kind in (ord('s'), ord('t'), ord('u'), ord('a'), ord('A'), ord('z'), ord('Z')):
            size = self.read(1)[0] if kind in (ord('z'), ord('Z')) else self.number()
            if size > MAX_TOC_BYTES:
                raise PrivacyError('archive-limit')
            raw = self.read(size)
            result = raw if kind == ord('s') else raw.decode('utf-8')
        elif kind in (ord('('), ord(')'), ord('[')):
            size = self.read(1)[0] if kind == ord(')') else self.number()
            if not 0 <= size <= MAX_MEMBERS * 4:
                raise PrivacyError('archive-limit')
            result = []
            if reference:
                self.refs[slot] = result
            result.extend(self.value(depth + 1) for _ in range(size))
            if kind != ord('['):
                result = tuple(result)
        elif kind == ord('{'):
            result = {}
            if reference:
                self.refs[slot] = result
            while self.data[self.position:self.position + 1] != b'0':
                key = self.value(depth + 1)
                if key in result:
                    raise PrivacyError('pyz-format')
                result[key] = self.value(depth + 1)
            self.read(1)
        else:
            # TYPE_CODE is deliberately forbidden in a table of contents.
            raise PrivacyError('pyz-format')
        if reference:
            self.refs[slot] = result
        return result


class ArchiveScanner:
    def __init__(self, policy):
        self.policy = policy
        self.expanded = self.members = self.files = 0

    def charge(self, size, *, compressed=None):
        self.members += 1
        self.expanded += size
        if (size < 0 or size > MAX_MEMBER_BYTES or self.members > MAX_MEMBERS
                or self.expanded > MAX_EXPANDED_BYTES
                or compressed is not None and size > max(1, compressed) * MAX_RATIO):
            raise PrivacyError('archive-limit')

    def inflate(self, data, expected=None):
        limit = min(MAX_MEMBER_BYTES, MAX_EXPANDED_BYTES - self.expanded)
        if expected is not None:
            if not 0 <= expected <= limit:
                raise PrivacyError('archive-limit')
            limit = expected
        decompressor = zlib.decompressobj()
        result = decompressor.decompress(data, limit + 1)
        if (len(result) > limit or not decompressor.eof or decompressor.unconsumed_tail
                or decompressor.unused_data or expected is not None and len(result) != expected):
            raise PrivacyError('archive-format')
        self.charge(len(result), compressed=len(data))
        return result

    def scan_paths(self, paths):
        seen = set()
        for item in paths:
            path = Path(item)
            if path.is_symlink() or not path.exists():
                raise PrivacyError('asset-unavailable')
            files = sorted(path.rglob('*')) if path.is_dir() else [path]
            for source in files:
                if source.is_symlink():
                    raise PrivacyError('asset-link')
                if source.is_dir():
                    continue
                if not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
                    raise PrivacyError('asset-size-limit')
                identity = source.resolve()
                if identity in seen:
                    continue
                seen.add(identity)
                name = source.relative_to(path).as_posix() if path.is_dir() else source.name
                self.policy.filename(name)
                data = source.read_bytes()
                self.files += 1
                self.charge(len(data))
                self.scan(data, name)
        return {'asset_files': self.files, 'archive_members': self.members,
                'expanded_bytes': self.expanded}

    def scan(self, data, name, depth=0):
        if depth > MAX_DEPTH:
            raise PrivacyError('archive-depth-limit')
        self.policy.content(data)
        if data.startswith(PNG_MAGIC) or name.lower().endswith('.png'):
            check_png(data)
            return
        if data.startswith(b'PYZ\0'):
            self.pyz(data, depth)
            return
        # ZIP must take precedence: a stored executable inside an outer ZIP
        # can expose a CArchive cookie before the outer ZIP is unpacked.
        if (data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'))
                or name.lower().endswith('.zip') or self.zip_directory(data, optional=True)):
            self.zip(data, depth)
            return
        if CARCHIVE_MAGIC in data:
            self.carchive(data, depth)
            return

    @staticmethod
    def zip_directory(data, optional=False):
        # Bound central-directory parsing before ZipFile allocates ZipInfo
        # objects; a forged low entry count must not hide millions of entries.
        position = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
        if position < 0 or position + 22 > len(data):
            if optional:
                return False
            raise PrivacyError('archive-format')
        _, disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack_from(
            '<4s4H2IH', data, position)
        if position + 22 + comment != len(data):
            if optional:
                return False
            raise PrivacyError('archive-format')
        if disk or directory_disk or disk_count != count:
            raise PrivacyError('archive-format')
        if count > MAX_MEMBERS or size > MAX_TOC_BYTES or count == 65535 or size == 0xffffffff:
            raise PrivacyError('archive-limit')
        start = position - size
        if start < 0 or start - offset < 0:
            raise PrivacyError('archive-format')
        cursor, actual = start, 0
        while cursor < position:
            if cursor + 46 > position or data[cursor:cursor + 4] != b'PK\x01\x02':
                raise PrivacyError('archive-format')
            name, extra, annotation = struct.unpack_from('<3H', data, cursor + 28)
            cursor += 46 + name + extra + annotation
            actual += 1
            if cursor > position or actual > MAX_MEMBERS:
                raise PrivacyError('archive-limit')
        if actual != count:
            raise PrivacyError('archive-format')
        return True

    def zip(self, data, depth):
        self.zip_directory(data)
        with zipfile.ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_MEMBERS:
                raise PrivacyError('archive-limit')
            names = set()
            for item in entries:
                self.policy.filename(item.filename.rstrip('/'))
                if item.filename in names or item.flag_bits & 1:
                    raise PrivacyError('archive-format')
                names.add(item.filename)
                if item.is_dir():
                    continue
                self.charge(item.file_size, compressed=item.compress_size)
                if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise PrivacyError('archive-format')
                with archive.open(item) as stream:
                    content = stream.read(item.file_size + 1)
                if len(content) != item.file_size:
                    raise PrivacyError('archive-format')
                if stat.S_ISLNK(item.external_attr >> 16):
                    self.policy.content(content)
                    target = content.decode('utf-8')
                    if PurePosixPath(target).is_absolute() or '..' in PurePosixPath(target).parts:
                        raise PrivacyError('asset-link')
                self.scan(content, item.filename, depth + 1)

    def carchive(self, data, depth):
        cookie = data.rfind(CARCHIVE_MAGIC)
        if cookie < 0 or cookie + COOKIE.size > len(data):
            raise PrivacyError('pyinstaller-format')
        _, length, toc_offset, toc_size, _, library = COOKIE.unpack_from(data, cookie)
        start = cookie + COOKIE.size - length
        if (start < 0 or toc_size > MAX_TOC_BYTES or not library.rstrip(b'\0')
                or start + toc_offset + toc_size != cookie):
            raise PrivacyError('pyinstaller-format')
        position, end = start + toc_offset, cookie
        names = set()
        while position < end:
            if position + TOC_ENTRY.size > end:
                raise PrivacyError('pyinstaller-format')
            size, offset, packed, expanded, compression, kind = TOC_ENTRY.unpack_from(data, position)
            if (size <= TOC_ENTRY.size or position + size > end or compression not in (0, 1)
                    or offset + packed > toc_offset):
                raise PrivacyError('pyinstaller-format')
            name_bytes = data[position + TOC_ENTRY.size:position + size].rstrip(b'\0')
            name = name_bytes.decode('utf-8')
            self.policy.filename(name)
            if kind == b'o':
                self.policy.content(name_bytes)
                position += size
                continue
            if name in names:
                raise PrivacyError('pyinstaller-format')
            names.add(name)
            content = data[start + offset:start + offset + packed]
            if compression:
                content = self.inflate(content, expanded)
            else:
                if packed != expanded:
                    raise PrivacyError('pyinstaller-format')
                self.charge(len(content))
            if kind == b'z' and not content.startswith(b'PYZ\0'):
                raise PrivacyError('pyz-format')
            self.scan(content, name, depth + 1)
            position += size

    def pyz(self, data, depth):
        if len(data) < 12:
            raise PrivacyError('pyz-format')
        offset = struct.unpack_from('!i', data, 8)[0]
        if not 12 <= offset < len(data):
            raise PrivacyError('pyz-format')
        parser = _MarshalTOC(data[offset:])
        toc = parser.value()
        if parser.position != len(parser.data):
            raise PrivacyError('pyz-format')
        entries = list(toc.items()) if isinstance(toc, dict) else toc
        if not isinstance(entries, (list, tuple)) or len(entries) > MAX_MEMBERS:
            raise PrivacyError('pyz-format')
        names = set()
        for entry in entries:
            if not isinstance(entry, (tuple, list)) or len(entry) != 2:
                raise PrivacyError('pyz-format')
            name, record = entry
            if isinstance(name, bytes):
                name = name.decode('utf-8')
            if not isinstance(name, str) or name in names:
                raise PrivacyError('pyz-format')
            names.add(name)
            if (not isinstance(record, (list, tuple)) or len(record) != 3
                    or any(type(x) is not int for x in record)):
                raise PrivacyError('pyz-format')
            kind, start, size = record
            # PYZ code-entry names are module identifiers, not filenames;
            # e.g. stdlib asyncio.log is a module, not a runtime log file.
            self.policy.filename(name.replace('.', '/') + '.pyc' if kind in (0, 1, 3) else name)
            if kind == 3 and size == 0:
                continue
            if kind not in (0, 1, 2) or start < 12 or size < 1 or start + size > offset:
                raise PrivacyError('pyz-format')
            content = self.inflate(data[start:start + size])
            self.scan(content, name, depth + 1)
