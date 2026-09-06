import pathlib,subprocess,time,os
base=pathlib.Path(pathlib.Path('/tmp/factorseal-release-drill-path').read_text())
binary=str(pathlib.Path('target/debug/factorseal').resolve())
for name in ['empty','populated']:
    root=base/name
    def run(*args):
        result=subprocess.run([binary,'--root',str(root),'--password-file',str(base/'password'),*args],capture_output=True,timeout=30)
        if result.returncode: raise RuntimeError(str(args)+': '+result.stderr.decode())
        return result
    run('grant-cli')
    with open(base/(name+'-reopen.log'),'wb') as log:
        agent=subprocess.Popen([binary,'--root',str(root),'--password-file',str(base/'password'),'agent'],stdout=log,stderr=log)
        try:
            for _ in range(100):
                if b'"state": "unsealed"' in run('status').stdout:break
                if agent.poll() is not None:raise RuntimeError('agent exited')
                time.sleep(.2)
            else:raise RuntimeError('unseal timeout')
            assert run('get','--project','release-drill','TOKEN').stdout==(base/'value').read_bytes()
            run('export',str(base/(name+'-reopened.factorseal')),'--passphrase-file',str(base/'archive-password'))
            print(name+': PASS native TPM re-unseal, exact bytes recovered, restored keyring exported again')
        finally:
            try: run('seal')
            except Exception as error: print(error)
            try: agent.wait(timeout=15)
            except subprocess.TimeoutExpired: agent.terminate();agent.wait(timeout=10)
