// Drives the browser extension in test Edge and Chrome profiles through the
// Chrome DevTools Protocol, and Desktop's browser prompt through drive.ps1,
// against the throwaway test vault. Run by browser-check.sh with Windows'
// Node; see README.md. Pages are served by the browser itself (Fetch domain)
// on made-up https://*.factorseal.test origins, so nothing reaches the
// network, and each run uses new origins, so logins saved by earlier runs do
// not interfere.
//
// --browsers is a base64-encoded JSON list of the browsers to drive: {kind,
// port, pid, load, fresh}. With one, the single-browser steps run; with two, the steps
// that check that consent never crosses from one browser to the other.
//
// Clicks and typing in pages and in the extension popup go through
// Input.dispatch*, which the page sees as trusted (isTrusted), as the save
// flow requires.
import {execFile} from 'node:child_process';
import {readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {promisify} from 'node:util';

const run = promisify(execFile);
const args = Object.fromEntries(process.argv.slice(2).map(a => a.match(/^--([^=]+)=(.*)$/s).slice(1)));
const extensionId = 'eljopjcihlpjipbefddajpoiefpfgdca';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

let failures = 0;
const report = (name, ok, detail = '') => {
    if (!ok) failures++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? `: ${detail}` : ''}`);
};

async function until(what, condition, ms = 10000) {
    const deadline = Date.now() + ms;
    for (;;) {
        const value = await condition().catch(() => undefined);
        if (value) return value;
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
        await sleep(200);
    }
}

const keyValues = stdout => Object.fromEntries(stdout.split(/\r?\n/).filter(l => l.includes('='))
    .map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
const powershell = (script, parameters) => run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, ...parameters],
    {windowsHide: true}).then(r => keyValues(r.stdout), error => keyValues(error.stdout || String(error)));

const fixture = name => readFile(new URL(`../../extensions/browser/fixtures/${name}`, import.meta.url), 'utf8');
const pages = {
    login: await fixture('login.html'),
    // Fields a person would call a login form, without a <form> element.
    formless: `<!doctype html><title>Formless</title><label>Username <input id="username" name="username"></label>
<label>Password <input id="password" type="password" name="password"></label><button>Log in</button>`,
};

// --- One test browser --------------------------------------------------------

async function connect({kind, port, pid, load, fresh}) {
    const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
    const socket = new WebSocket(version.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        socket.addEventListener('open', resolve, {once: true});
        socket.addEventListener('error', reject, {once: true});
    });
    let nextId = 0;
    const calls = new Map();
    const listeners = new Set();
    socket.addEventListener('message', event => {
        const message = JSON.parse(event.data);
        if (message.id && calls.has(message.id)) {
            const call = calls.get(message.id);
            calls.delete(message.id);
            if (message.error) call.reject(new Error(`${call.method}: ${message.error.message}`));
            else call.resolve(message.result);
        } else {
            for (const listener of listeners) listener(message);
        }
    });
    // A browser can leave a call unanswered (a closed target, a blocked
    // dialog); fail the step instead of waiting forever.
    const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => {
            calls.delete(id);
            reject(new Error(`${kind}: ${method} got no answer in 20 s`));
        }, 20000);
        calls.set(id, {resolve: v => { clearTimeout(timer); resolve(v); }, reject: e => { clearTimeout(timer); reject(e); }, method});
        socket.send(JSON.stringify({id, method, params, sessionId}));
    });
    const b = {kind, name: kind === 'chrome' ? 'Chrome' : 'Edge', socket, send};

    const targets = async () => (await send('Target.getTargets')).targetInfos;
    const attach = async targetId => (await send('Target.attachToTarget', {targetId, flatten: true})).sessionId;
    const evaluate = async (sessionId, expression) => {
        const {result, exceptionDetails} = await send('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true}, sessionId);
        if (exceptionDetails) throw new Error(exceptionDetails.exception?.description || exceptionDetails.text);
        return result.value;
    };
    // A trusted click at the centre of the element the selector names.
    b.click = async (sessionId, selector) => {
        const box = await evaluate(sessionId, `(() => {
            const e = document.querySelector(${JSON.stringify(selector)});
            if (!e) return null;
            e.scrollIntoView({block: 'center'});
            const r = e.getBoundingClientRect();
            return {x: r.left + r.width / 2, y: r.top + r.height / 2};
        })()`);
        if (!box) throw new Error(`no ${selector}`);
        for (const type of ['mousePressed', 'mouseReleased'])
            await send('Input.dispatchMouseEvent', {type, x: box.x, y: box.y, button: 'left', clickCount: 1}, sessionId);
    };
    b.type = async (sessionId, selector, text) => {
        await b.click(sessionId, selector);
        await send('Input.insertText', {text}, sessionId);
    };

    // Manifest V3 service workers stop when idle. Opening an extension page
    // wakes this one; an attached session then keeps it running.
    const worker = async () => {
        const find = async () => (await targets()).find(t => t.type === 'service_worker' && t.url.startsWith(`chrome-extension://${extensionId}/`));
        let target = await find();
        if (!target) {
            const {targetId} = await send('Target.createTarget', {url: `chrome-extension://${extensionId}/popup.html`, background: true});
            target = await until('the extension service worker', find);
            await send('Target.closeTarget', {targetId});
        }
        return attach(target.targetId);
    };
    // Chrome no longer honours --load-extension: load (or reload) the
    // extension through the DevTools Protocol. A browser left running from an
    // earlier check still runs the extension it loaded then: reload it from
    // disk, as its reload button would.
    const running = async () => (await targets()).find(t => t.type === 'service_worker' && t.url.startsWith(`chrome-extension://${extensionId}/`));
    if (load) {
        // Loading it again replaces a running worker; attaching to the old one
        // leaves calls unanswered.
        const old = await running();
        await send('Extensions.loadUnpacked', {path: load});
        if (old) await until('the old service worker to stop', async () => (await running())?.targetId !== old.targetId, 5000).catch(() => {});
    } else {
        const background = await worker();
        const loaded = (await targets()).find(t => t.type === 'service_worker' && t.url.startsWith(`chrome-extension://${extensionId}/`)).targetId;
        await evaluate(background, 'chrome.runtime.reload()').catch(() => {});
        await until('the extension to reload', async () => !(await targets()).some(t => t.targetId === loaded));
    }
    const background = await worker();
    b.extension = expression => evaluate(background, expression);
    b.paired = () => b.extension(`chrome.storage.local.get('paired').then(s => s.paired === true)`);
    // The profile's public key, which Desktop shows to tell profiles apart.
    b.key = () => b.extension(`chrome.storage.local.get('pairing').then(s => s.pairing?.public)`);

    // The toolbar popup, opened as a click on the toolbar button would.
    const popupUrl = `chrome-extension://${extensionId}/popup.html`;
    b.closePopup = async () => {
        // Edge refuses to open the popup while the last one is still closing.
        const popups = async () => (await targets()).filter(t => t.url === popupUrl);
        for (const t of await popups()) await send('Target.closeTarget', {targetId: t.targetId}).catch(() => {});
        await until('the popup to close', async () => (await popups()).length === 0, 5000);
    };
    b.openPopup = async () => {
        await b.closePopup();
        await b.extension(`chrome.windows.getLastFocused().then(w => chrome.action.openPopup({windowId: w.id}))`);
        const target = await until('the extension popup', async () => (await targets()).find(t => t.url === popupUrl && t.attached === false));
        const session = await attach(target.targetId);
        await until('the popup to render', () => evaluate(session, `document.readyState === 'complete'`));
        return {session, targetId: target.targetId};
    };
    b.popupStatus = popup => evaluate(popup.session, `document.getElementById('status').textContent`);
    b.popupOpen = async popup => (await targets()).some(t => t.targetId === popup.targetId);
    // The popup disables its buttons while a request is pending.
    b.press = async (popup, id) => {
        await until(`#${id} to be enabled`, () => evaluate(popup.session, `(() => { const b = document.getElementById(${JSON.stringify(id)}); return !!b && !b.disabled && !b.hidden && !!b.offsetParent; })()`), 10000)
            .catch(async error => { throw new Error(`${error.message}; the popup says: ${await b.popupStatus(popup).catch(() => '?')}`); });
        await b.click(popup.session, `#${id}`);
    };

    // One tab, whose requests to *.factorseal.test the browser answers itself.
    // Tabs left from earlier runs still hold their login pages, which ask
    // Desktop again whenever the browser gets the focus back; close them.
    const {targetId} = await send('Target.createTarget', {url: 'about:blank'});
    for (const t of await targets())
        if (t.type === 'page' && t.targetId !== targetId) await send('Target.closeTarget', {targetId: t.targetId}).catch(() => {});
    const sessionId = await attach(targetId);
    let served = pages.login;
    listeners.add(message => {
        if (message.method !== 'Fetch.requestPaused' || message.sessionId !== sessionId) return;
        const {requestId, request} = message.params;
        const body = request.url.endsWith('/favicon.ico') ? '' : served;
        send('Fetch.fulfillRequest', {requestId, responseCode: body ? 200 : 404,
            responseHeaders: [{name: 'Content-Type', value: 'text/html; charset=utf-8'}],
            body: Buffer.from(body).toString('base64')}, sessionId).catch(() => {});
    });
    await send('Fetch.enable', {patterns: [{urlPattern: 'https://*.factorseal.test/*'}]}, sessionId);
    await send('Page.enable', {}, sessionId);
    b.tab = {
        session: sessionId,
        async open(url, page = 'login') {
            served = pages[page];
            await send('Page.bringToFront', {}, sessionId);
            await send('Page.navigate', {url}, sessionId);
            await until(`${url} to load`, () => evaluate(sessionId, `location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`));
        },
        fields: () => evaluate(sessionId, `({username: document.querySelector('[name=username]').value, password: document.querySelector('[name=password]').value, url: location.href})`),
    };

    // Which window Windows has in front. The browser's own chrome.windows
    // focus state can stay true while another app is in front, so ask
    // Windows. A browser window, not one of the browser's own bubbles (such
    // as the one about developer-mode extensions Edge shows after starting),
    // which also take focus. Edge's titles end "— Microsoft​ Edge".
    const title = kind === 'chrome' ? '*Google Chrome' : '*Microsoft*Edge';
    b.foreground = (action = 'get') => powershell(args.foreground, ['-Action', action, '-ProcessId', pid, '-TitleLike', title]);
    b.inFront = async (action = 'get') => (await b.foreground(action)).match === 'True';
    // The extension asks Desktop only for a tab in a focused window, and a
    // person is looking at the browser then; put it in front for real.
    b.focus = async () => {
        await send('Page.bringToFront', {}, sessionId);
        await b.extension(`chrome.windows.getLastFocused().then(w => chrome.windows.update(w.id, {focused: true}))`);
        if (!(await until(`the test ${b.name} in front`, () => b.inFront('raise'), 5000).then(() => true, () => false)))
            throw new Error(`Windows kept the test ${b.name} out of the foreground (in front: ${(await b.foreground()).title})`);
    };
    // After Desktop's prompt closes, the browser should be in front again: the
    // person is back on the page they were using, e.g. to submit the login.
    b.focusedBack = () => until(`${b.name} to get the focus back`, () => b.inFront(), 3000).then(() => true, async () => {
        const front = await b.foreground();
        console.log(`      in front instead: ${front.title} (${front.process})`);
        return false;
    });
    b.filled = () => until('the fields to fill', async () => { const f = await b.tab.fields(); return f.password && f; });

    // A freshly started Edge shows its bubble about developer-mode extensions
    // a few seconds in, taking the foreground; close it before any step runs.
    // Chrome has none, so this only waits.
    if (fresh) {
        const deadline = Date.now() + 15000;
        while (Date.now() < deadline && !(await b.foreground('raise')).closed) await sleep(500);
    }
    return b;
}

const browsers = JSON.parse(Buffer.from(args.browsers, 'base64').toString());
if (args.close) {
    for (const {port} of browsers) {
        const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
        const socket = new WebSocket(version.webSocketDebuggerUrl);
        await new Promise(resolve => socket.addEventListener('open', resolve, {once: true}));
        socket.send(JSON.stringify({id: 1, method: 'Browser.close'}));
    }
    await sleep(1000);
    process.exit(0);
}

// --- Desktop's browser prompt --------------------------------------------------

const prompt = (action, extra = []) => powershell(args.drive, ['-Action', action, '-DesktopPid', args.desktopPid, '-Title', 'Browser access', ...extra]);
const promptOpen = async () => (await prompt('find')).popup_open === 'True';
async function waitPrompt(ms = 10000) {
    await until('the browser prompt', promptOpen, ms);
    return prompt('find');
}
// No prompt for a while: the extension did not ask Desktop anything.
async function staysQuiet(ms = 4000) {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) { if (await promptOpen()) return false; await sleep(300); }
    return true;
}
// What a screen reader finds in Desktop's windows: every name UI Automation
// exposes. Read from a UTF-8 file, as console output mangles "•" and "…".
async function screenReader() {
    const out = join(tmpdir(), `factorseal-uia-${process.pid}.txt`);
    await powershell(args.uiaDump, ['-DesktopPid', args.desktopPid, '-Out', out]);
    const dump = (await readFile(out, 'utf8')).replace(/^\uFEFF/, '');
    await rm(out, {force: true});
    return [...dump.matchAll(/ name='([^']*)'/g)].map(m => m[1]);
}
// Reports which of the texts a screen reader cannot find in the prompt.
async function reads(name, texts) {
    const names = await screenReader();
    const missing = texts.filter(t => !names.includes(t));
    report(`${name}: a screen reader reads the prompt`, !missing.length, missing.length ? `missing ${JSON.stringify(missing)}` : '');
}
const password = ['-PasswordFile', args.passwordFile];
const vault = async (...command) => (await run(args.cli, ['--root', args.root, ...command], {windowsHide: true})).stdout;

// --- Steps -------------------------------------------------------------------------

const stamp = Date.now().toString(36);
const origin = name => `https://${name}-${stamp}.factorseal.test`;
const site = origin('login');
const username = `check-${stamp}`;
const secret = `pw-${stamp}-${Math.random().toString(36).slice(2)}`;
const account = ['-Name', `* · ${username}`];

// --only=name,name runs just the steps whose names start so; pairing and
// saving always run.
const only = args.only?.split(',');
let saved = false;
const needsSave = () => { if (!saved) throw new Error('needs the save step, which stores the login it fills'); };
async function step(name, body) {
    if (only && !['pair', 'save'].includes(name.split(':')[0]) && !only.some(o => name.startsWith(o))) return;
    try { await body(); } catch (error) { report(name, false, error.message); }
}

// A request left waiting by an interrupted run would answer for this one.
if (await promptOpen()) {
    await prompt('deny');
    console.log('      denied a prompt left open by an earlier run');
}

const connected = [];
for (const description of browsers) connected.push(await connect(description));
const prefix = connected.length > 1 ? b => `${b.name} ` : () => '';

// Pairs a browser profile through the popup and Desktop's prompt.
async function pairProfile(b) {
    await b.tab.open(`${site}/`);
    await b.focus();
    const popup = await b.openPopup();
    await b.press(popup, 'pair');
    const found = await waitPrompt();
    report(`${prefix(b)}pair: prompt opens`, true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
    await reads(`${prefix(b)}pair`, ['Pair browser profile', 'Browser extension',
        'Allow this browser profile to request logins. Every fill still needs your approval.',
        `Profile key: ${(await b.key()).slice(0, 16)}…`, 'Pair browser', 'Deny']);
    await prompt('press', ['-Name', 'Pair browser']);
    await until('pairing to finish', b.paired, 15000);
    report(`${prefix(b)}pair`, true);
}

for (const b of connected) {
    await step(`pair: ${b.name}`, async () => {
        if (await b.paired()) report(`${prefix(b)}pair`, true, 'already paired');
        else await pairProfile(b);
    });
}

const [b, other] = connected;
const {tab, extension} = b;

await step('save', async () => {
    await tab.open(`${site}/`);
    await b.focus();
    // Nothing is stored for the new origin yet: no prompt on load.
    report(`${prefix(b)}save: no prompt before submitting`, await staysQuiet(3000));
    await b.type(tab.session, '[name=username]', username);
    await b.type(tab.session, '[name=password]', secret);
    await b.click(tab.session, 'button[type=submit]');
    const found = await waitPrompt().catch(async error => {
        const facts = await extension(`chrome.windows.getLastFocused({populate: true}).then(w => JSON.stringify({status, focused: w.focused, activeTab: w.tabs.find(t => t.active)?.url}))`);
        throw new Error(`${error.message}; extension: ${facts}; page: ${JSON.stringify(await tab.fields())}; front: ${(await b.foreground()).title}`);
    });
    report(`${prefix(b)}save: prompt opens`, true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
    await reads(`${prefix(b)}save`, ['Save login', site, 'Save this website’s login to Personal secrets.',
        `Username: ${username}`, 'Password: ••••••••', 'Applies only to this request.']);
    await prompt('press', ['-Name', 'Save login']);
    await until('the save to finish', () => extension(`status === 'saved'`), 15000);
    saved = true;
    report(`${prefix(b)}save`, true);
});

if (!other) {
    await step('resubmit unchanged', async () => {
        needsSave();
        await tab.open(`${site}/`);
        await b.focus();
        // The stored login is offered on load; deny that first.
        await waitPrompt();
        await prompt('deny');
        await b.type(tab.session, '[name=username]', username);
        await b.type(tab.session, '[name=password]', secret);
        await b.click(tab.session, 'button[type=submit]');
        report('resubmit unchanged: no save prompt', await staysQuiet(4000));
    });

    await step('fill', async () => {
        needsSave();
        await tab.open(`${site}/`);
        await b.focus();
        const found = await waitPrompt();
        report('fill: prompt opens', true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
        await reads('fill', ['Fill a login', site, 'Choose one account to fill once. The browser will check the original page again.',
            'Applies only to this request.']);
        await prompt('press', account);
        const fields = await b.filled();
        report('fill: fields filled', fields.username === username && fields.password === secret);
        report('fill: not submitted', fields.url === `${site}/`);
        report('fill: the browser gets the focus back', await b.focusedBack());
    });

    for (const [how, action] of [['Deny', 'deny'], ['Escape', 'escape']]) {
        await step(`${how}`, async () => {
            needsSave();
            await tab.open(`${site}/`);
            await b.focus();
            await waitPrompt();
            await prompt(action);
            await until('the denial', () => extension(`status === 'denied'`), 5000);
            report(`${how}: the browser gets the focus back`, await b.focusedBack());
            const fields = await tab.fields();
            report(`${how}: denied, fields empty`, !fields.username && !fields.password);
            // Typing changes the page; that must not ask again.
            await b.type(tab.session, '[name=username]', 'x');
            report(`${how}: typing afterwards stays quiet`, await staysQuiet(3000));
        });
    }

    await step('no match', async () => {
        await tab.open(`${origin('nomatch')}/`);
        await b.focus();
        report('no match: no prompt while unsealed', await staysQuiet(4000));
        report('no match: the browser keeps the focus', await b.inFront());
        const popup = await b.openPopup();
        const status = await until('a status', () => b.popupStatus(popup), 5000);
        report('no match: popup says so', status === 'No matching login found.', status);
        await b.closePopup();
    });

    await step('Check this page', async () => {
        await tab.open(`${origin('formless')}/`, 'formless');
        await b.focus();
        let popup = await b.openPopup();
        await b.press(popup, 'retry');
        const status = await until('a status', () => b.popupStatus(popup), 10000);
        report('Check this page: no form is reported', status === 'No complete login form found on this page.', status);
        report('Check this page: popup stays open without a form', await b.popupOpen(popup));
        await b.closePopup();
        needsSave();
        await tab.open(`${site}/`);
        await b.focus();
        await waitPrompt();
        await prompt('deny');
        popup = await b.openPopup();
        await b.press(popup, 'retry');
        await sleep(1000);
        report('Check this page: popup closes with a form', !(await b.popupOpen(popup)));
        await b.focus();
        await waitPrompt();
        report('Check this page: the page is checked again', true);
        await prompt('deny');
    });

    await step('sealed fill', async () => {
        needsSave();
        await vault('seal');
        await tab.open(`${site}/`);
        await b.focus();
        const found = await waitPrompt();
        report('sealed fill: prompt opens', true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
        report('sealed fill: prompt lies on one screen', found.on_screen === 'True', found.bounds);
        await reads('sealed fill', ['Fill a login', site, 'Unlock your vault to continue here.', 'Vault password', 'Unlock to continue']);
        const unlocked = await prompt('unlock-popup', [...password, ...account]);
        report('sealed fill: unlocks, then offers the login', unlocked.unlocked === 'True');
        await prompt('press', account);
        const fields = await b.filled();
        report('sealed fill: fields filled', fields.username === username && fields.password === secret);
    });

    // Disconnecting also goes through Desktop; then the profile pairs again.
    await step('pair again', async () => {
        // A page with no stored login, so no fill request keeps the popup busy.
        await tab.open(`${origin('pairing')}/`);
        await b.focus();
        const popup = await b.openPopup();
        await b.send('Runtime.evaluate', {expression: `document.getElementById('profile').open = true`}, popup.session);
        await b.press(popup, 'revoke');
        await waitPrompt();
        await reads('disconnect', ['Disconnect browser profile', 'Browser extension',
            'Remove this profile’s permission to request logins.', `Profile key: ${(await b.key()).slice(0, 16)}…`, 'Disconnect profile']);
        await prompt('press', ['-Name', 'Disconnect profile']);
        await until('the profile to disconnect', async () => !(await b.paired()), 15000);
        report('disconnect', true);
        await pairProfile(b);
    });
} else {
    // Two browser profiles, each paired, each with its own session with
    // Desktop. A request waiting in one must not be answered for the other:
    // Desktop takes one request at a time and tells the other it is busy, and
    // the approval fills only the page that asked.
    const empty = async c => { const f = await c.tab.fields(); return !f.username && !f.password; };
    for (const [first, second, answer] of [[b, other, 'approve'], [other, b, 'deny']]) {
        const name = `consent: ${first.name} asks, ${second.name} waits, ${answer}`;
        await step(name, async () => {
            needsSave();
            // Each browser is in front before its page loads, as when a person
            // opens the page: the extension asks only for a focused window.
            await first.focus();
            await first.tab.open(`${site}/`);
            await waitPrompt();
            await second.focus();
            await second.tab.open(`${site}/`);
            await until(`${second.name} to be told Desktop is busy`, () => second.extension(`status === 'busy'`), 10000)
                .catch(async error => { throw new Error(`${error.message}; its status: ${await second.extension('status')}; prompt open: ${await promptOpen()}`); });
            report(`${name}: the second browser is told Desktop is busy`, true);
            // The prompt names the profile that asked, not the one waiting.
            await prompt('press', ['-Name', 'Technical details +']);
            const names = await screenReader();
            report(`${name}: the prompt shows the asking profile's key`,
                names.includes(`Profile public key: ${await first.key()}`) && !names.includes(`Profile public key: ${await second.key()}`));
            if (answer === 'approve') {
                await prompt('press', account);
                const fields = await first.filled();
                report(`${name}: the asking browser is filled`, fields.username === username && fields.password === secret);
            } else {
                await prompt('deny');
                await until('the denial', () => first.extension(`status === 'denied'`), 5000);
                report(`${name}: the asking browser is denied`, await empty(first));
            }
            await sleep(1500);
            report(`${name}: nothing reaches the waiting browser`, await empty(second) && await second.extension(`status === 'busy'`));
            // The waiting browser's own request, asked again, gets its own prompt.
            await second.focus();
            const popup = await second.openPopup();
            await second.press(popup, 'retry');
            await second.focus();
            await waitPrompt();
            await prompt('press', account);
            const fields = await second.filled();
            report(`${name}: asked again, the second browser gets its own fill`, fields.username === username && fields.password === secret);
        });
    }
}

for (const c of connected) { await c.closePopup().catch(() => {}); c.socket.close(); }
console.log(failures ? `FAIL (${failures})` : 'PASS');
process.exit(failures ? 1 : 0);
