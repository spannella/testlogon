#!/usr/bin/env python3
"""APIK-E3 (#118) filemanager parity — idempotent region-scoped registry patcher.

Promotes the real filemanager product surface (presign/complete upload flow, core
mutations, sharing symmetry, read-side) from fail-closed exemptions into
API_KEY_ROUTE_SCOPE_REGISTRY with filemanager:{read,write,share}; clears the copy /
batch-upload / crm-metadata / crm-search unmapped drift. Intentional blocks
(mount-credential ops + admin/* + client-telemetry + purge-deleted + usage/*) stay
fail-closed exempt. Idempotent: rebuilds the filemanager registry block + strips the
promoted exemption keys on every run.
"""
import io, os, re, sys

REG = os.environ.get('APIK_REG', os.path.join(os.getcwd(), 'app/services/api_key_route_scope_registry.py'))

# --- desired filemanager registry surface (all entitlement_required=True, matching existing FM/messager/newsfeed rows) ---
READ = [
    ('GET', '/v1/fs/list'), ('GET', '/v1/fs/download'), ('GET', '/v1/fs/info'),
    ('GET', '/v1/fs/search'), ('GET', '/v1/fs/search-text'), ('GET', '/v1/fs/preview'),
    ('GET', '/v1/fs/thumbnail'), ('GET', '/v1/fs/crm-search'),
    ('GET', '/v1/fs/shared-with'), ('GET', '/v1/fs/shared-with-me'), ('GET', '/v1/fs/shared-list'),
    ('GET', '/v1/fs/shared-info'), ('GET', '/v1/fs/shared-download'), ('GET', '/v1/fs/shared-preview'),
    ('GET', '/v1/fs/shared-thumbnail'),
    ('POST', '/v1/fs/download-zip'), ('POST', '/v1/fs/shared-download-zip'),
]
WRITE = [
    ('POST', '/v1/fs/folder'), ('POST', '/v1/fs/upload'), ('POST', '/v1/fs/presign-upload'),
    ('POST', '/v1/fs/complete-upload'), ('POST', '/v1/fs/batch-upload'),
    ('POST', '/v1/fs/rename-file'), ('POST', '/v1/fs/rename-folder'), ('POST', '/v1/fs/move'),
    ('POST', '/v1/fs/copy'), ('POST', '/v1/fs/move-resume'), ('POST', '/v1/fs/move-rollback'),
    ('POST', '/v1/fs/upload-zip'), ('POST', '/v1/fs/upload-archive'),
    ('POST', '/v1/fs/shared-move'), ('POST', '/v1/fs/shared-rename-file'), ('POST', '/v1/fs/shared-rename-folder'),
    ('POST', '/v1/fs/shared-folder'), ('POST', '/v1/fs/shared-upload'), ('POST', '/v1/fs/shared-upload-archive'),
    ('POST', '/v1/fs/shared-upload-zip'),
    ('PATCH', '/v1/fs/crm-metadata'),
    ('DELETE', '/v1/fs'), ('DELETE', '/v1/fs/file'), ('DELETE', '/v1/fs/folder'),
    ('DELETE', '/v1/fs/shared-file'), ('DELETE', '/v1/fs/shared-folder'),
]
SHARE = [
    ('POST', '/v1/fs/share'), ('POST', '/v1/fs/unshare'),
]

def rid(m, p):
    return '%s:%s' % (m, p)

FM_ROWS = {}
for m, p in READ:
    FM_ROWS[rid(m, p)] = 'read'
for m, p in WRITE:
    FM_ROWS[rid(m, p)] = 'write'
for m, p in SHARE:
    FM_ROWS[rid(m, p)] = 'share'

# exemption keys promoted into the registry -> must be deleted from the exemption dict
PROMOTED_EXEMPTIONS = set(FM_ROWS.keys()) - {
    'GET:/v1/fs/list', 'POST:/v1/fs/folder', 'POST:/v1/fs/upload', 'GET:/v1/fs/download', 'POST:/v1/fs/share',
}
# copy/batch-upload/crm-metadata/crm-search were UNMAPPED (never exempt) -> no exemption line to remove
PROMOTED_EXEMPTIONS -= {'POST:/v1/fs/copy', 'POST:/v1/fs/batch-upload', 'PATCH:/v1/fs/crm-metadata', 'GET:/v1/fs/crm-search'}

def build_block():
    lines = []
    lines.append('    # File Manager -- APIK-E3 (#118): real fs product surface promoted from fail-closed')
    lines.append('    # exemptions. read/write/share; entitlement_required=True. Intentional blocks')
    lines.append('    # (mount-credential ops + admin/* + client-telemetry + purge-deleted + usage/*) stay exempt.')
    lines.append('    # filemanager:admin inherits read+write+share (see api_key_capabilities).')
    for key in sorted(FM_ROWS.keys()):
        scope = FM_ROWS[key]
        lines.append('    "%s": {"product": "filemanager", "required_scopes": ["filemanager:%s"], "entitlement_required": True},' % (key, scope))
    return [l + '\n' for l in lines]

def main():
    with io.open(REG, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 1) locate registry open + the first '# Newsfeed' marker (end of fm block region)
    open_idx = next(i for i, l in enumerate(lines) if l.startswith('API_KEY_ROUTE_SCOPE_REGISTRY'))
    news_idx = next(i for i in range(open_idx, len(lines)) if '# Newsfeed' in lines[i])

    new_lines = lines[:open_idx + 1] + build_block() + lines[news_idx:]

    # 2) strip promoted exemption keys from the exemption dict
    def is_promoted_exemption(line):
        s = line.strip()
        # only strip EXEMPTION rows (they carry "reason"); never the freshly-inserted
        # registry rows (which carry "product") that share the same "<key>": prefix.
        if '"reason":' not in s:
            return False
        for k in PROMOTED_EXEMPTIONS:
            if s.startswith('"%s":' % k):
                return True
        return False

    final = [l for l in new_lines if not is_promoted_exemption(l)]

    with io.open(REG, 'w', encoding='utf-8') as f:
        f.writelines(final)

    print('E3 patch applied: fm_registry_rows=%d promoted_exemptions_removed=%d' % (len(FM_ROWS), len(PROMOTED_EXEMPTIONS)))

if __name__ == '__main__':
    main()
