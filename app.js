let boundary = '';
let transport = 'remote';
let inboxTimer = null;
const $ = selector => document.querySelector(selector);
const files = $('#files');
const list = $('#file-list');
if (new URLSearchParams(location.search).has('desktop')) document.body.classList.add('desktop');

async function init() {
  try {
    boundary = (await fetch('/api/session', { cache: 'no-store' }).then(r => r.json())).token;
    const status = await req('/api/relay/status');
    if (!status.ok) throw new Error('Could not read relay settings');
    const current = await status.json();
    $('#settings-status').textContent = current.configured
      ? `Relay ready · ${current.auth_mode === 'gh' ? 'GitHub CLI' : 'fine-grained token'} · secret values hidden`
      : 'Relay settings incomplete. Configure a private repository and pairing key to send remotely.';
    if (!current.configured) setMode('local');
  } catch (_) {
    $('#settings-status').textContent = 'Relay settings are unavailable.';
    setMode('local');
  }
}

function req(url, opts = {}) {
  opts.headers = { ...(opts.headers || {}), 'X-Teleport-Request': boundary };
  if (opts.body instanceof File || opts.body instanceof Blob) {
    if (opts.body.type) opts.headers['Content-Type'] = opts.body.type;
  } else if (opts.body && typeof opts.body === 'object') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  return fetch(url, opts);
}

const auth = (code, name) => ({ 'X-Recipient-Code': code, 'X-Recipient-Name': encodeURIComponent(name) });
function size(n) { return n < 1024 ** 2 ? `${n} B` : `${(n / 1024 ** 2).toFixed(1)} MB`; }
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
async function hash(blob) {
  const b = await blob.arrayBuffer();
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', b))].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function responseJson(response) {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

files.addEventListener('change', () => {
  list.innerHTML = [...files.files].map(f => `<div class="file-row"><span>${escapeHtml(f.name)}</span><span>${size(f.size)}</span></div>`).join('');
});
$('#drop').addEventListener('dragover', e => { e.preventDefault(); e.currentTarget.classList.add('drag'); });
$('#drop').addEventListener('dragleave', e => e.currentTarget.classList.remove('drag'));
$('#drop').addEventListener('drop', e => { e.preventDefault(); e.currentTarget.classList.remove('drag'); files.files = e.dataTransfer.files; files.dispatchEvent(new Event('change')); });

function setMode(value) {
  transport = value;
  document.querySelectorAll('[data-mode]').forEach(button => button.classList.toggle('active', button.dataset.mode === value));
  $('#local-receive').classList.toggle('hidden', value !== 'local');
  $('#remote-receive').classList.toggle('hidden', value !== 'remote');
  $('#send-kicker').textContent = value === 'remote' ? 'PRIVATE HANDOFF' : 'LOCAL HANDOFF';
  $('#send').innerHTML = value === 'remote' ? 'Send encrypted files <span>↗</span>' : 'Create local handoff <span>↗</span>';
  $('#file-limit').textContent = value === 'remote' ? 'Encrypted before upload · up to 32 MiB' : 'Files stay in this device · up to 128 MiB';
  $('#send-notice').textContent = value === 'remote'
    ? 'File names and transfer details are encrypted with your shared pairing key.'
    : 'Local transport only. Files are not encrypted in this mode.';
  $('#footer-scope').textContent = value === 'remote' ? 'Private relay · GitHub private release assets' : 'Local transport · this device only';
  if (inboxTimer) { clearInterval(inboxTimer); inboxTimer = null; }
}
document.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => setMode(button.dataset.mode)));

function panel(id, title, content) {
  const element = $(id);
  element.classList.remove('hidden');
  element.innerHTML = `<div class="panel-head"><div><p class="eyebrow">TRANSFER STATUS</p><h2>${title}</h2></div></div>${content}`;
  element.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
}

$('#send-form').addEventListener('submit', async e => {
  e.preventDefault();
  const chosen = [...files.files];
  if (!chosen.length) return;
  const button = $('#send');
  button.disabled = true;
  button.textContent = 'Checking file hashes…';
  try {
    if (transport === 'remote') await sendRemote(chosen);
    else await sendLocal(chosen);
  } catch (err) {
    panel('#active', 'Transfer could not start', `<p class="error">${escapeHtml(err.message)}</p>`);
  } finally {
    button.disabled = false;
    button.innerHTML = transport === 'remote' ? 'Send encrypted files <span>↗</span>' : 'Create local handoff <span>↗</span>';
  }
});

async function sendRemote(chosen) {
  const meta = [];
  let total = 0;
  for (const file of chosen) {
    total += file.size;
    if (total > 32 * 1024 ** 2) throw new Error('Transfer exceeds 32 MiB');
    meta.push({ name: file.name, size: file.size, sha256: await hash(file) });
  }
  const header = new TextEncoder().encode(JSON.stringify({ recipient: $('#recipient').value, hours: Number($('#hours').value), files: meta }));
  const body = new Uint8Array(4 + header.length + total);
  new DataView(body.buffer).setUint32(0, header.length, false);
  body.set(header, 4);
  let offset = 4 + header.length;
  for (const file of chosen) { const bytes = new Uint8Array(await file.arrayBuffer()); body.set(bytes, offset); offset += bytes.length; }
  const result = await responseJson(await req('/api/relay/send', { method: 'POST', body: new Blob([body], { type: 'application/octet-stream' }) }));
  panel('#active', 'Encrypted transfer sent', `<div class="status"><p>Transfer ID <span class="receipt">${escapeHtml(result.transfer_id)}</span></p><p>Asset reference <span class="receipt">${escapeHtml(result.asset)}</span></p><p>${result.files} file(s) · expires ${new Date(result.expires * 1000).toLocaleString()}</p><p class="fine">Share the transfer ID and asset reference with the recipient. Share the pairing key separately using a trusted channel.</p><button id="check-receipt" class="secondary file-action">Check for verified receipt</button><div id="sender-receipt-status" class="fine" aria-live="polite"></div></div>`);
  $('#check-receipt').onclick = () => checkRemoteReceipt(result.transfer_id, result.asset);
}

async function checkRemoteReceipt(id, asset) {
  const slot = $('#sender-receipt-status');
  slot.textContent = 'Checking the receiver receipt…';
  try {
    const receipt = await responseJson(await req('/api/relay/receipt', { method: 'POST', body: { transfer_id: id, asset } }));
    slot.innerHTML = `<p class="ok">Recipient receipt verified · ${receipt.files.length} file(s).</p><button id="remote-cleanup" class="secondary file-action">Remove encrypted relay copy</button><p class="fine">Cleanup removes the encrypted transfer asset after this authenticated receipt check.</p>`;
    $('#remote-cleanup').onclick = async () => {
      if (!confirm('Remove the encrypted transfer asset from the private relay?')) return;
      const result = await responseJson(await req('/api/relay/cleanup', { method: 'POST', body: { transfer_id: id, asset } }));
      slot.textContent = result.cleaned ? 'Encrypted transfer asset removed.' : 'Cleanup did not complete.';
    };
  } catch (err) { slot.textContent = err.message; }
}

async function sendLocal(chosen) {
  const meta = [];
  for (const file of chosen) meta.push({ name: file.name, size: file.size, sha256: await hash(file) });
  const created = await responseJson(await req('/api/transfers', { method: 'POST', body: { recipient: $('#recipient').value, hours: Number($('#hours').value), files: meta } }));
  panel('#active', 'Sending your files', `<p class="support">If upload stops, reselect these files below and enter the same ID and code to resume.</p><div class="status"><p>Handoff ID <span class="receipt">${created.id}</span></p><p>Recipient code <span class="receipt">${created.code}</span></p><p id="progress-label">Preparing chunks…</p><div class="progress"><i id="bar"></i></div><p class="fine">Local transport only. Anyone with both values can access this transfer.</p></div>`);
  await uploadLocal(created, chosen);
}

async function uploadLocal(t, chosen) {
  const total = t.files.reduce((a, f) => a + f.size, 0) || 1;
  let done = 0;
  for (let i = 0; i < chosen.length; i++) {
    const file = chosen[i], meta = t.files[i];
    if (file.name !== meta.name || file.size !== meta.size || await hash(file) !== meta.sha256) throw new Error(`${file.name}: selected file does not match the original`);
    for (let n = 0; n < meta.chunks; n++) {
      const blob = file.slice(n * 1024 ** 2, Math.min(file.size, (n + 1) * 1024 ** 2));
      const r = await req(`/api/transfers/${t.id}/file/${i}`, { method: 'POST', headers: { ...auth(t.code, t.recipient), 'X-Chunk-Index': n, 'X-Chunk-SHA256': await hash(blob) }, body: blob });
      await responseJson(r);
      done += blob.size;
      $('#progress-label').textContent = `${Math.min(done, total).toLocaleString()} of ${total.toLocaleString()} bytes uploaded`;
      $('#bar').style.width = `${Math.min(100, done / total * 100)}%`;
    }
  }
  await responseJson(await req(`/api/transfers/${t.id}/verify`, { method: 'POST', body: { code: t.code, recipient: t.recipient } }));
  panel('#active', 'Files verified', `<p class="ok">Every uploaded file matches its SHA-256 hash.</p><p class="support">Handoff ID <span class="receipt">${t.id}</span><br>Recipient code <span class="receipt">${t.code}</span></p><p class="fine">The recipient must use this same running service.</p>`);
}

$('#remote-receive-form').addEventListener('submit', async e => {
  e.preventDefault();
  await receiveRemoteOnce();
});
async function receiveRemoteOnce() {
  const slot = $('#remote-receive-state');
  slot.innerHTML = '<p>Checking the private relay and verifying the encrypted transfer…</p>';
  try {
    const result = await responseJson(await req('/api/relay/receive', { method: 'POST', body: { transfer_id: $('#remote-id').value.trim(), asset: $('#remote-asset').value.trim(), recipient: $('#remote-name').value.trim() } }));
    const files = result.files.map(file => `<li>${escapeHtml(file.name)} · ${size(file.size)} · SHA-256 checked</li>`).join('');
    slot.innerHTML = `<div class="status"><p class="ok">Files saved and verified in Downloads/Teleport.</p><ul class="received-list">${files}</ul><p class="fine">An authenticated receipt was published for the sender. The original sender files were not changed.</p></div>`;
    if (inboxTimer) { clearInterval(inboxTimer); inboxTimer = null; }
  } catch (err) { slot.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`; }
}

$('#watch-remote').addEventListener('click', async () => {
  const button = $('#watch-remote');
  const slot = $('#remote-receive-state');
  if (inboxTimer) { clearInterval(inboxTimer); inboxTimer = null; button.textContent = 'Watch for delivery'; slot.textContent = 'Watching stopped.'; return; }
  if (!$('#remote-id').value.trim() || !$('#remote-asset').value.trim() || !$('#remote-name').value.trim()) {
    slot.innerHTML = '<p class="error">Enter transfer ID, asset reference, and recipient first.</p>'; return;
  }
  button.textContent = 'Stop watching';
  slot.textContent = 'Watching the private relay every 15 seconds. This window can stay open while the sender uploads.';
  const poll = async () => {
    try {
      const status = await responseJson(await req('/api/relay/available', { method: 'POST', body: { transfer_id: $('#remote-id').value.trim(), asset: $('#remote-asset').value.trim() } }));
      if (status.available) await receiveRemoteOnce();
      else slot.textContent = `No matching transfer yet · checked ${new Date().toLocaleTimeString()}`;
    } catch (err) { slot.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`; }
  };
  await poll();
  if (!slot.querySelector('.ok') && button.textContent === 'Stop watching') inboxTimer = setInterval(poll, 15000);
});

$('#receive-form').addEventListener('submit', async e => {
  e.preventDefault();
  const id = $('#transfer-id').value.trim(), code = $('#code').value.trim(), recipient = $('#receive-name').value.trim(), state = $('#receive-state');
  state.innerHTML = '<p>Checking recipient access…</p>';
  try {
    const m = await responseJson(await req(`/api/transfers/${id}/details`, { method: 'POST', body: { code, recipient } }));
    if (Date.now() / 1000 > m.expires) throw new Error('This handoff has expired');
    if (!m.verified) {
      state.innerHTML = `<div class="status"><h3>Upload can resume</h3><p>${m.files.length} file(s), ${m.files.reduce((a, f) => a + f.size, 0).toLocaleString()} bytes</p><label>Select the same files<input id="resume-files" type="file" multiple></label><button id="resume" class="secondary file-action">Resume upload</button><p class="fine">Already received chunks are checked and skipped.</p></div>`;
      $('#resume').onclick = () => resumeLocal(id, code, recipient, m);
      return;
    }
    state.innerHTML = `<div class="status"><h3>Ready to receive</h3><p>Recipient: ${escapeHtml(m.recipient)}</p><p>${m.files.length} file(s) · ${m.files.reduce((a, f) => a + f.size, 0).toLocaleString()} bytes</p><button id="download" class="primary file-action">Download and verify files</button><div id="receive-progress"></div></div>`;
    $('#download').onclick = () => receiveLocal(id, code, recipient, m);
  } catch (err) { state.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`; }
});

async function resumeLocal(id, code, recipient, manifest) {
  const chosen = [...$('#resume-files').files], state = $('#receive-state');
  try {
    if (chosen.length !== manifest.files.length) throw new Error('Select every original file');
    for (let i = 0; i < chosen.length; i++) if (chosen[i].name !== manifest.files[i].name || chosen[i].size !== manifest.files[i].size || await hash(chosen[i]) !== manifest.files[i].sha256) throw new Error(`${manifest.files[i].name}: selected bytes do not match the original`);
    for (let i = 0; i < chosen.length; i++) {
      const file = chosen[i], meta = manifest.files[i];
      for (let n = 0; n < meta.chunks; n++) {
        if (meta.received.includes(n)) continue;
        const blob = file.slice(n * 1024 ** 2, Math.min(file.size, (n + 1) * 1024 ** 2));
        await responseJson(await req(`/api/transfers/${id}/file/${i}`, { method: 'POST', headers: { ...auth(code, recipient), 'X-Chunk-Index': n, 'X-Chunk-SHA256': await hash(blob) }, body: blob }));
      }
    }
    await responseJson(await req(`/api/transfers/${id}/verify`, { method: 'POST', body: { code, recipient } }));
    state.innerHTML = '<p class="ok">All files verified. You can now receive this handoff.</p>';
  } catch (err) { state.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`; }
}

async function receiveLocal(id, code, recipient, manifest) {
  const out = $('#receive-progress'), verified = [];
  try {
    for (let i = 0; i < manifest.files.length; i++) {
      const file = manifest.files[i];
      out.innerHTML = `<p>Downloading ${escapeHtml(file.name)}…</p>`;
      const response = await req(`/api/transfers/${id}/download/${i}`, { headers: auth(code, recipient) });
      if (!response.ok) throw new Error((await response.json()).error);
      const blob = await response.blob(), actual = await hash(blob);
      if (actual !== file.sha256 || blob.size !== file.size) throw new Error(`${file.name}: downloaded bytes do not match. Receipt blocked.`);
      verified.push({ name: file.name, size: file.size, sha256: actual, blob });
    }
    for (const file of verified) {
      const anchor = document.createElement('a'); anchor.href = URL.createObjectURL(file.blob); anchor.download = file.name; anchor.click(); setTimeout(() => URL.revokeObjectURL(anchor.href), 30000);
    }
    const result = await responseJson(await req(`/api/transfers/${id}/receive`, { method: 'POST', body: { code, recipient, hashes: verified.map(f => f.sha256) } }));
    const receipt = JSON.stringify(result.receipt);
    out.innerHTML = `<p class="ok">Received bytes verified; file downloads requested.</p><p class="receipt">Receipt fingerprint: ${await hash(new Blob([receipt]))}</p><details><summary>View receipt</summary><pre class="receipt">${escapeHtml(receipt)}</pre></details><button id="cleanup" class="secondary file-action">Clean up sender copy</button><p class="fine">Cleanup deletes only Teleport's stored transfer chunks after this verified receive.</p>`;
    $('#cleanup').onclick = async () => {
      if (!confirm('Delete Teleport’s stored copy for this handoff? Your selected source files will not be touched.')) return;
      const clean = await responseJson(await req(`/api/transfers/${id}/cleanup`, { method: 'POST', body: { code, recipient } }));
      out.innerHTML = clean.cleaned ? '<p class="ok">Teleport transfer copy removed.</p>' : '<p class="error">Cleanup did not complete.</p>';
    };
  } catch (err) { out.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`; }
}

$('#settings-toggle').addEventListener('click', async () => {
  $('#settings').classList.toggle('hidden');
  if (!$('#settings').classList.contains('hidden')) {
    $('#setting-token').value = '';
    $('#setting-key').value = '';
  }
});
$('#auth-mode').addEventListener('change', () => { $('#token-wrap').classList.toggle('hidden', $('#auth-mode').value === 'gh'); });
$('#settings-form').addEventListener('submit', async e => {
  e.preventDefault();
  const resultSlot = $('#settings-status');
  resultSlot.textContent = 'Saving private relay settings…';
  try {
    const result = await responseJson(await req('/api/relay/configure', { method: 'POST', body: {
      owner: $('#setting-owner').value.trim(), repo: $('#setting-repo').value.trim(), channel: $('#setting-channel').value.trim(),
      recipient: $('#setting-recipient').value.trim(), auth_mode: $('#auth-mode').value,
      token: $('#setting-token').value || null, pairing_key: $('#setting-key').value || null
    } }));
    $('#setting-token').value = ''; $('#setting-key').value = '';
    $('#recipient').value = $('#setting-recipient').value.trim();
    resultSlot.textContent = 'Relay settings saved outside the application folder.';
    if (result.pairing_key) $('#pair-output').innerHTML = `<p class="fine">Copy this new pairing key now and share it separately with the recipient. Teleport will not show it again.</p><code class="pair-code">${escapeHtml(result.pairing_key)}</code>`;
    else $('#pair-output').innerHTML = '<p class="fine">Pairing key saved. The value is hidden and cannot be retrieved from Settings.</p>';
    $('#pair-output').classList.remove('hidden');
    setMode('remote');
  } catch (err) { resultSlot.textContent = err.message; }
});
$('#remove-key').addEventListener('click', async () => {
  if (!confirm('Remove the saved pairing key? This disables relay send and receive until configured again.')) return;
  try { await responseJson(await req('/api/relay/remove-pairing-key', { method: 'POST', body: {} })); $('#settings-status').textContent = 'Pairing key removed.'; setMode('local'); }
  catch (err) { $('#settings-status').textContent = err.message; }
});
$('#remove-settings').addEventListener('click', async () => {
  if (!confirm('Remove saved relay credentials and pairing key from this device?')) return;
  try { await responseJson(await req('/api/relay/remove-settings', { method: 'POST', body: {} })); $('#settings-status').textContent = 'Relay settings removed.'; setMode('local'); }
  catch (err) { $('#settings-status').textContent = err.message; }
});

init();
