// Drives the browser extension in a test Edge profile through the Chrome
// DevTools Protocol, and Desktop's browser prompt through drive.ps1, against
// the throwaway test vault. Run by browser-check.sh with Windows' Node; see
// README.md. Pages are served by the browser itself (Fetch domain) on made-up
// https://*.factorseal.test origins, so nothing reaches the network, and each
// run uses new origins, so logins saved by earlier runs do not interfere.
//
// Clicks and typing in pages and in the extension popup go through
// Input.dispatch*, which the page sees as trusted (isTrusted), as the save
// flow requires.
import {execFile} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {promisify} from 'node:util';

const run = promisify(execFile);
const args = Object.fromEntries(process.argv.slice(2).map(a => a.match(/^--([^=]+)=(.*)$/s).slice(1)));
const extensionId = 'eljopjcihlpjipbefddajpoiefpfgdca';
const port = args.port || '9333';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

let failures = 0;
const report = (name, ok, detail = '') => {
    if (!ok) failures++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? `: ${detail}` : ''}`);
};

// --- DevTools Protocol -----------------------------------------------------

const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
const socket = new WebSocket(version.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, {once: true});
    socket.addEventListener('error', reject, {once: true});
});
if (args.close) {
    socket.send(JSON.stringify({id: 1, method: 'Browser.close'}));
    await sleep(1000);
    process.exit(0);
}
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
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++nextId;
    calls.set(id, {resolve, reject, method});
    socket.send(JSON.stringify({id, method, params, sessionId}));
});

async function until(what, condition, ms = 10000) {
    const deadline = Date.now() + ms;
    for (;;) {
        const value = await condition().catch(() => undefined);
        if (value) return value;
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
        await sleep(200);
    }
}

const targets = async () => (await send('Target.getTargets')).targetInfos;
const attach = async targetId => (await send('Target.attachToTarget', {targetId, flatten: true})).sessionId;

async function evaluate(sessionId, expression) {
    const {result, exceptionDetails} = await send('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true}, sessionId);
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description || exceptionDetails.text);
    return result.value;
}

// A trusted click at the centre of the element the selector names.
async function click(sessionId, selector) {
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
}

async function type(sessionId, selector, text) {
    await click(sessionId, selector);
    await send('Input.insertText', {text}, sessionId);
}

// --- The extension -----------------------------------------------------------

// Manifest V3 service workers stop when idle. Opening an extension page wakes
// this one; an attached session then keeps it running.
async function worker() {
    const find = async () => (await targets()).find(t => t.type === 'service_worker' && t.url.startsWith(`chrome-extension://${extensionId}/`));
    let target = await find();
    if (!target) {
        const {targetId} = await send('Target.createTarget', {url: `chrome-extension://${extensionId}/popup.html`, background: true});
        target = await until('the extension service worker', find);
        await send('Target.closeTarget', {targetId});
    }
    return attach(target.targetId);
}

// A browser left running from an earlier check still runs the extension it
// loaded then: reload it from disk, as its reload button would.
let background = await worker();
const loaded = (await targets()).find(t => t.type === 'service_worker' && t.url.startsWith(`chrome-extension://${extensionId}/`)).targetId;
await evaluate(background, 'chrome.runtime.reload()').catch(() => {});
await until('the extension to reload', async () => !(await targets()).some(t => t.targetId === loaded));
background = await worker();
const extension = expression => evaluate(background, expression);

// The toolbar popup, opened as a click on the toolbar button would.
async function openPopup() {
    await closePopup();
    await extension(`chrome.windows.getLastFocused().then(w => chrome.action.openPopup({windowId: w.id}))`);
    const target = await until('the extension popup', async () =>
        (await targets()).find(t => t.url === `chrome-extension://${extensionId}/popup.html` && t.attached === false));
    const session = await attach(target.targetId);
    await until('the popup to render', () => evaluate(session, `document.readyState === 'complete'`));
    return {session, targetId: target.targetId};
}
// Edge refuses to open the popup while the last one is still closing.
async function closePopup() {
    const popup = async () => (await targets()).filter(t => t.url === `chrome-extension://${extensionId}/popup.html`);
    for (const t of await popup()) await send('Target.closeTarget', {targetId: t.targetId}).catch(() => {});
    await until('the popup to close', async () => (await popup()).length === 0, 5000);
}
// The popup disables its buttons while a request is pending.
async function press(popup, id) {
    await until(`#${id} to be enabled`, () => evaluate(popup.session, `(() => { const b = document.getElementById(${JSON.stringify(id)}); return !!b && !b.disabled && !b.hidden && !!b.offsetParent; })()`), 10000)
        .catch(async error => { throw new Error(`${error.message}; the popup says: ${await popupStatus(popup.session).catch(() => '?')}`); });
    await click(popup.session, `#${id}`);
}
const popupOpen = async targetId => (await targets()).some(t => t.targetId === targetId);
const popupStatus = session => evaluate(session, `document.getElementById('status').textContent`);

// --- Pages -------------------------------------------------------------------

const fixture = name => readFile(new URL(`../../extensions/browser/fixtures/${name}`, import.meta.url), 'utf8');
const pages = {
    login: await fixture('login.html'),
    // Fields a person would call a login form, without a <form> element.
    formless: `<!doctype html><title>Formless</title><label>Username <input id="username" name="username"></label>
<label>Password <input id="password" type="password" name="password"></label><button>Log in</button>`,
};

const tab = await (async () => {
    const {targetId} = await send('Target.createTarget', {url: 'about:blank'});
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
    return {
        targetId, session: sessionId,
        async open(url, page = 'login') {
            served = pages[page];
            await send('Page.bringToFront', {}, sessionId);
            await send('Page.navigate', {url}, sessionId);
            await until(`${url} to load`, () => evaluate(sessionId, `location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`));
        },
        fields: () => evaluate(sessionId, `({username: document.querySelector('[name=username]').value, password: document.querySelector('[name=password]').value, url: location.href})`),
    };
})();

// Which window Windows has in front. Edge's own chrome.windows focus state
// can stay true while another app is in front, so ask Windows.
async function foreground(action = 'get') {
    const {stdout} = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', args.foreground,
        '-Action', action, '-ProcessId', args.edgePid, '-TitleLike', '*Microsoft*Edge'], {windowsHide: true}).catch(error => ({stdout: error.stdout || ''}));
    return Object.fromEntries(stdout.split(/\r?\n/).filter(l => l.includes('=')).map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
}
// A browser window, not one of Edge's own bubbles (such as the one about
// developer-mode extensions it shows after starting), which also take focus.
const edgeInFront = async (action = 'get') => (await foreground(action)).match === 'True';

// The extension asks Desktop only for a tab in a focused window, and a person
// is looking at the browser then; put it in front for real.
async function focusBrowser() {
    await send('Page.bringToFront', {}, tab.session);
    await extension(`chrome.windows.getLastFocused().then(w => chrome.windows.update(w.id, {focused: true}))`);
    if (!(await until('the test browser in front', () => edgeInFront('raise'), 5000).then(() => true, () => false)))
        throw new Error(`Windows kept the test browser out of the foreground (in front: ${(await foreground()).title})`);
}

// A freshly started Edge shows its bubble about developer-mode extensions a
// few seconds in, taking the foreground; close it before any step runs.
if (args.fresh) {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline && !(await foreground('raise')).closed) await sleep(500);
}

// --- Desktop's browser prompt --------------------------------------------------

async function prompt(action, extra = []) {
    const {stdout} = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', args.drive,
        '-Action', action, '-DesktopPid', args.desktopPid, '-Title', 'Browser access', ...extra], {windowsHide: true})
        .catch(error => ({stdout: error.stdout || String(error)}));
    return Object.fromEntries(stdout.split(/\r?\n/).filter(l => l.includes('=')).map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
}
// After Desktop's prompt closes, the browser should be in front again: the
// person is back on the page they were using, e.g. to submit the filled login.
const browserFocused = () => until('the browser to get the focus back', () => edgeInFront(), 3000).then(() => true, async () => {
    const front = await foreground();
    console.log(`      in front instead: ${front.title} (${front.process})`);
    return false;
});
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
const password = ['-PasswordFile', args.passwordFile];
const vault = async (...command) => (await run(args.cli, ['--root', args.root, ...command], {windowsHide: true})).stdout;

// --- Scenarios -------------------------------------------------------------------

const stamp = Date.now().toString(36);
const origin = name => `https://${name}-${stamp}.factorseal.test`;
const site = origin('login');
const username = `check-${stamp}`;
const secret = `pw-${stamp}-${Math.random().toString(36).slice(2)}`;

// --only=name,name runs just those steps (pairing still runs when needed).
const only = args.only?.split(',');
// Steps after 'save' fill the login it stored.
let saved = false;
const needsSave = () => { if (!saved) throw new Error('needs the save step, which stores the login it fills'); };
async function step(name, body) {
    if (only && name !== 'pair' && !only.includes(name)) return;
    try { await body(); } catch (error) { report(name, false, error.message); }
}

await step('pair', async () => {
    if ((await extension(`chrome.storage.local.get('paired').then(s => s.paired === true)`))) {
        report('pair', true, 'already paired');
        return;
    }
    await tab.open(`${site}/`);
    await focusBrowser();
    const popup = await openPopup();
    await press(popup, 'pair');
    const found = await waitPrompt();
    report('pair: prompt opens', true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
    await prompt('press', ['-Name', 'Pair browser']);
    await until('pairing to finish', () => extension(`chrome.storage.local.get('paired').then(s => s.paired === true)`), 15000);
    report('pair', true);
});

await step('save', async () => {
    await tab.open(`${site}/`);
    await focusBrowser();
    // Nothing is stored for the new origin yet: no prompt on load.
    report('save: no prompt before submitting', await staysQuiet(3000));
    await type(tab.session, '[name=username]', username);
    await type(tab.session, '[name=password]', secret);
    await click(tab.session, 'button[type=submit]');
    const found = await waitPrompt().catch(async error => {
        const facts = await extension(`chrome.windows.getLastFocused({populate: true}).then(w => JSON.stringify({status, focused: w.focused, activeTab: w.tabs.find(t => t.active)?.url}))`);
        const fields = JSON.stringify(await tab.fields());
        throw new Error(`${error.message}; extension: ${facts}; page: ${fields}; front: ${(await foreground()).title}`);
    });
    report('save: prompt opens', true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
    await prompt('press', ['-Name', 'Save login']);
    await until('the save to finish', () => extension(`status === 'saved'`), 15000);
    saved = true;
    report('save', true);
});

await step('resubmit unchanged', async () => {
    needsSave();
    await tab.open(`${site}/`);
    await focusBrowser();
    // The stored login is offered on load; deny that first.
    await waitPrompt();
    await prompt('deny');
    await type(tab.session, '[name=username]', username);
    await type(tab.session, '[name=password]', secret);
    await click(tab.session, 'button[type=submit]');
    report('resubmit unchanged: no save prompt', await staysQuiet(4000));
});

await step('fill', async () => {
    needsSave();
    await tab.open(`${site}/`);
    await focusBrowser();
    const found = await waitPrompt();
    report('fill: prompt opens', true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
    await prompt('press', ['-Name', `* · ${username}`]);
    const fields = await until('the fields to fill', async () => { const f = await tab.fields(); return f.password && f; });
    report('fill: fields filled', fields.username === username && fields.password === secret);
    report('fill: not submitted', fields.url === `${site}/`);
    report('fill: the browser gets the focus back', await browserFocused());
});

for (const [how, action] of [['Deny', 'deny'], ['Escape', 'escape']]) {
    await step(`${how}`, async () => {
        needsSave();
        await tab.open(`${site}/`);
        await focusBrowser();
        await waitPrompt();
        await prompt(action);
        await until('the denial', () => extension(`status === 'denied'`), 5000);
        report(`${how}: the browser gets the focus back`, await browserFocused());
        const fields = await tab.fields();
        report(`${how}: denied, fields empty`, !fields.username && !fields.password);
        // Typing changes the page; that must not ask again.
        await type(tab.session, '[name=username]', 'x');
        report(`${how}: typing afterwards stays quiet`, await staysQuiet(3000));
    });
}

await step('no match', async () => {
    await tab.open(`${origin('nomatch')}/`);
    await focusBrowser();
    report('no match: no prompt while unsealed', await staysQuiet(4000));
    report('no match: the browser keeps the focus', await edgeInFront());
    const popup = await openPopup();
    const status = await until('a status', () => popupStatus(popup.session), 5000);
    report('no match: popup says so', status === 'No matching login found.', status);
    await closePopup();
});

await step('Check this page', async () => {
    await tab.open(`${origin('formless')}/`, 'formless');
    await focusBrowser();
    let popup = await openPopup();
    await press(popup, 'retry');
    const status = await until('a status', () => popupStatus(popup.session), 10000);
    report('Check this page: no form is reported', status === 'No complete login form found on this page.', status);
    report('Check this page: popup stays open without a form', await popupOpen(popup.targetId));
    await closePopup();
    needsSave();
    await tab.open(`${site}/`);
    await focusBrowser();
    await waitPrompt();
    await prompt('deny');
    popup = await openPopup();
    await press(popup, 'retry');
    await sleep(1000);
    report('Check this page: popup closes with a form', !(await popupOpen(popup.targetId)));
    await focusBrowser();
    await waitPrompt();
    report('Check this page: the page is checked again', true);
    await prompt('deny');
});

await step('sealed fill', async () => {
    needsSave();
    await vault('seal');
    await tab.open(`${site}/`);
    await focusBrowser();
    const found = await waitPrompt();
    report('sealed fill: prompt opens', true, `foreground=${found.foreground} on_screen=${found.on_screen}`);
    report('sealed fill: prompt lies on one screen', found.on_screen === 'True', found.bounds);
    const unlocked = await prompt('unlock-popup', [...password, '-Name', `* · ${username}`]);
    report('sealed fill: unlocks, then offers the login', unlocked.unlocked === 'True');
    await prompt('press', ['-Name', `* · ${username}`]);
    const fields = await until('the fields to fill', async () => { const f = await tab.fields(); return f.password && f; });
    report('sealed fill: fields filled', fields.username === username && fields.password === secret);
});

await closePopup();
console.log(failures ? `FAIL (${failures})` : 'PASS');
socket.close();
process.exit(failures ? 1 : 0);
