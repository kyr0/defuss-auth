"""Create a source archive and checksum manifest; do not publish or modify upstream."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib, json
root=Path(__file__).resolve().parent.parent
version=json.loads((root/'package.json').read_text())['version']
release=root/'release'; release.mkdir(exist_ok=True)
archive=release/f'defuss-auth-{version}-source.zip'
skip={'node_modules','.git','release','build','output','data','tmp','var','coverage','input','__pycache__'}
with ZipFile(archive,'w',ZIP_DEFLATED) as z:
    for p in sorted(root.rglob('*')):
        rel=p.relative_to(root)
        if p.is_file() and not p.is_symlink() and not skip.intersection(rel.parts) and not (p.name.startswith('.env') and p.name!='.env.example'):
            z.write(p, f'defuss-auth-{version}/{rel.as_posix()}')
(release/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(release.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
print(archive)
