import sys,json,hashlib
from pathlib import Path
mode,path,scan_id=sys.argv[1:]
data=Path(path).read_bytes()
record={'scan_id':scan_id,'content_sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'verdict':'BLOCK' if mode=='block' or b'BLOCK_ME' in data else 'ALLOW','reason':'fixture rule'}
if mode=='stderr_flood':sys.stderr.write('diagnostic\n'*20000);sys.stderr.flush()
text=json.dumps(record)
if mode=='partial':sys.stdout.write(text[:len(text)//2]);sys.exit(0)
for part in (text[:9],text[9:]+'\n'):sys.stdout.write(part);sys.stdout.flush()
if mode=='bad_exit':sys.exit(7)
