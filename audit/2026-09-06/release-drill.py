import os, pathlib, subprocess, tempfile, time, json
base=pathlib.Path(tempfile.mkdtemp(prefix='factorseal-release-drill.'))
os.chmod(base,0o700)
pathlib.Path('/tmp/factorseal-release-drill-path').write_text(str(base))
binary=str(pathlib.Path('target/debug/factorseal').resolve())
password=base/'password'; password.write_text('synthetic native orchard violet lantern 2026');password.chmod(0o600)
archivepass=base/'archive-password';archivepass.write_text('synthetic archive orchard violet lantern 2026');archivepass.chmod(0o600)
value=base/'value';value.write_bytes(b'release drill exact bytes\x00\n')
manager=base/'manager.json';manager.write_text('{"items":[{"name":"A","type":1,"login":{"password":"first"}},{"name":"A","type":1,"login":{"password":"second"}},{"name":"A (2)","type":1,"login":{"password":"third"}}]}')
logs=[]
def run(root,*args,ok=True):
    p=subprocess.run([binary,'--root',str(root),'--password-file',str(password),*map(str,args)],capture_output=True,timeout=90)
    logs.append((list(map(str,args)),p.returncode,p.stdout.decode(errors='replace'),p.stderr.decode(errors='replace')))
    if ok and p.returncode: raise RuntimeError(f'{args}: {p.stderr.decode()}')
    return p
agents=[]
try:
    for name in ['source','empty','populated']:
        root=base/name
        run(root,'init','--unlock','password')
        agentlog=open(base/(name+'-agent.log'),'wb')
        p=subprocess.Popen([binary,'--root',str(root),'--password-file',str(password),'agent','--idle-seconds','600'],stdout=agentlog,stderr=agentlog)
        agents.append((root,p,agentlog))
        for _ in range(100):
            status=run(root,'status',ok=False)
            if b'unsealed' in status.stdout: break
            if p.poll() is not None: raise RuntimeError('agent exited: '+(base/(name+'-agent.log')).read_text())
            time.sleep(.2)
        else: raise RuntimeError('agent startup timed out')
        if name=='source':
            run(root,'set','--project','release-drill','TOKEN','--value-file',value)
            assert run(root,'get','--project','release-drill','TOKEN').stdout==value.read_bytes()
            run(root,'import',manager,'--format','bitwarden-json')
            run(root,'import',manager,'--format','bitwarden-json')
            output=base/'personal.json';run(root,'export',output,'--format','bitwarden-json')
            items=json.loads(output.read_text())['items'];assert len(items)==3
            assert {x['login']['password'] for x in items}=={'first','second','third'}
            run(root,'export',base/'source.factorseal','--passphrase-file',archivepass)
        else:
            if name=='populated':run(root,'set','--project','release-drill','UNRELATED','--value-file',value)
            run(root,'import',base/'source.factorseal','--passphrase-file',archivepass)
            assert run(root,'get','--project','release-drill','TOKEN').stdout==value.read_bytes()
            run(root,'import','/tmp/factorseal-release-v1.factorseal','--passphrase-file',archivepass)
            run(root,'import','/tmp/factorseal-release-v1.factorseal','--passphrase-file',archivepass)
            run(root,'import','/tmp/factorseal-release-v1.factorseal','--passphrase-file',archivepass,'--replace-existing')
            run(root,'set','--project','release-drill','NEXT_WRITE','--value-file',value)
            if name=='populated':assert run(root,'get','--project','release-drill','UNRELATED').stdout==value.read_bytes()
            run(root,'export',base/(name+'.factorseal'),'--passphrase-file',archivepass)
        run(root,'permissions','list')
        run(root,'seal');p.wait(timeout=15);agentlog.close()
    print('PASS: native TPM CLI, exact-byte storage, duplicate/repeat imports, v2 backup restore, v1 import keep/replace into empty/populated vaults, next writes, permission listing, explicit seal')
finally:
    for root,p,log in agents:
        if p.poll() is None:
            run(root,'seal',ok=False)
            try:p.wait(timeout=15)
            except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=10)
        log.close()
    (base/'commands.json').write_text(json.dumps(logs,indent=2))
    print('Evidence directory:',base)
