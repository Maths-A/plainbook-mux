const toast = document.getElementById('toast');
const cards = document.getElementById('cards');
const statTotal = document.getElementById('stat-total');
const statRunning = document.getElementById('stat-running');
const lastRefresh = document.getElementById('last-refresh');
const launchCommand = document.getElementById('launch-command');
const systemUsage = document.getElementById('system-usage');
const totalUsage = document.getElementById('total-usage');
const runtimeSizeText = document.getElementById('runtime-size-text');
const deleteRuntimeBtn = document.getElementById('delete-runtime-btn');
const stopAllBtn = document.getElementById('stop-all-btn');

const accessCodesModal = document.getElementById('access-codes-modal');
const accessCodeRowsBody = document.getElementById('access-code-rows');
const accessCodesError = document.getElementById('access-codes-error');
const accessCodesStatus = document.getElementById('access-codes-status');
const saveAccessCodesBtn = document.getElementById('save-access-codes-btn');
const tabBtnStudy = document.getElementById('tab-btn-study');
const tabBtnGenerated = document.getElementById('tab-btn-generated');
const tabPanelStudy = document.getElementById('tab-panel-study');
const tabPanelGenerated = document.getElementById('tab-panel-generated');
const generatedCodesError = document.getElementById('generated-codes-error');
const generatedStudyStats = document.getElementById('generated-study-stats');
const generatedRowsBody = document.getElementById('generated-code-rows');
const generatedStudySelect = document.getElementById('generated-study-select');
const generatedCountInput = document.getElementById('generated-count');
const generatedProfessorInput = document.getElementById('generated-professor');
const generateCodesBtn = document.getElementById('generate-codes-btn');
let accessCodeRows = [];
let studyCodes = [];
let generatedCodeRows = [];

// The two flags every study-code launch gets, no matter what -- rendered as
// locked tags (not editable) and re-unioned into every row before it is
// saved, so neither removing a tag nor hand-editing the underlying JSON can
// drop them. Kept in sync with MANDATORY_INSTANCE_FLAGS in app.py.
const MANDATORY_INSTANCE_FLAGS = [
  { key: 'user-study', hint: 'Locks notebook management; shows the Submit button' },
  { key: 'log', hint: 'Records participant actions into the notebook for replay' },
];
const MANDATORY_INSTANCE_FLAG_KEYS = MANDATORY_INSTANCE_FLAGS.map((f) => f.key);
// What a study-code entry gets when it has no "flags" of its own -- matches
// what every launch got unconditionally before this feature existed.
const DEFAULT_INSTANCE_FLAGS = [...MANDATORY_INSTANCE_FLAG_KEYS];

// Everything past user-study/log is free text an admin types in directly --
// deliberately NOT checked against a fixed list of known plainbook flags, so
// a newly added plainbook flag can be used the same day without an admin.js
// change. That also means a typo (or anything else) is passed straight
// through as --<text> to the plainbook process; it is on the admin to type
// it right. build_plainbook_command appends each array entry as one argv
// token via subprocess (no shell), so even an entry containing spaces can
// only ever become one weird flag name -- plainbook's own argparse rejects
// it and the instance fails to start, it cannot inject separate arguments.
function normalizeFlagText(text) {
  return String(text || '').trim().replace(/^-+/, '');
}

// Unions MANDATORY_INSTANCE_FLAG_KEYS into `flags` (mandatory ones first, in
// their fixed order), keeps the rest in the order they were entered, drops
// blanks and duplicates. The one place both the render path and the save
// path route a row's flags through, so the two can never disagree about
// what actually ends up in the saved config.
function withMandatoryFlags(flags) {
  const extras = [];
  const seen = new Set(MANDATORY_INSTANCE_FLAG_KEYS);
  for (const raw of (flags || [])) {
    const flag = normalizeFlagText(raw);
    if (flag && !seen.has(flag)) {
      seen.add(flag);
      extras.push(flag);
    }
  }
  return [...MANDATORY_INSTANCE_FLAG_KEYS, ...extras];
}

function switchAccessModalTab(tabName) {
  const isStudy = tabName === 'study';
  tabBtnStudy.classList.toggle('active', isStudy);
  tabBtnGenerated.classList.toggle('active', !isStudy);
  tabPanelStudy.classList.toggle('active', isStudy);
  tabPanelGenerated.classList.toggle('active', !isStudy);
  if (!isStudy) {
    loadStudyCodes();
  }
}

function formatUnixTimestamp(ts) {
  if (!ts) {
    return '-';
  }
  return new Date(ts * 1000).toLocaleString();
}

function formatRelativeTime(ts) {
  if (!ts || ts <= 0) {
    return '-';
  }
  const now = Date.now() / 1000; // current unix timestamp in seconds
  const secondsAgo = Math.max(0, now - ts);
  if (secondsAgo < 60) {
    return `${Math.floor(secondsAgo)}s ago`;
  }
  if (secondsAgo < 3600) {
    return `${Math.floor(secondsAgo / 60)}m ago`;
  }
  if (secondsAgo < 86400) {
    return `${Math.floor(secondsAgo / 3600)}h ago`;
  }
  return `${Math.floor(secondsAgo / 86400)}d ago`;
}

function renderStudyOptions() {
  if (!studyCodes.length) {
    generatedStudySelect.innerHTML = '<option value="">No study codes available</option>';
    generatedStudySelect.disabled = true;
    generateCodesBtn.disabled = true;
    return;
  }
  generatedStudySelect.disabled = false;
  generateCodesBtn.disabled = false;
  generatedStudySelect.innerHTML = studyCodes
    .map((study) => `<option value="${escapeHtml(study.code)}">${escapeHtml(study.code)}</option>`)
    .join('');
}

function renderGeneratedCodeRows() {
  renderGeneratedStudyStats();
  if (!generatedCodeRows.length) {
    generatedRowsBody.innerHTML = '<tr><td colspan="7" class="footnote">No generated codes yet.</td></tr>';
    return;
  }

  const studyOptionsHtml = studyCodes
    .map((study) => `<option value="${escapeHtml(study.code)}">${escapeHtml(study.code)}</option>`)
    .join('');

  generatedRowsBody.innerHTML = generatedCodeRows.map((row, index) => `
    <tr>
      <td class="code">${escapeHtml(row.code)}</td>
      <td>
        <select data-generated-index="${index}" data-generated-field="study" style="width:100%; border:1px solid rgba(255,255,255,0.16); border-radius:10px; background:rgba(255,255,255,0.04); color:var(--text); padding:8px 10px; font:inherit;">
          ${studyOptionsHtml}
        </select>
      </td>
      <td>
        <input data-generated-index="${index}" data-generated-field="professor" value="${escapeHtml(row.professor || '')}" placeholder="—" style="width:100%; border:1px solid rgba(255,255,255,0.16); border-radius:10px; background:rgba(255,255,255,0.04); color:var(--text); padding:8px 10px; font:inherit;">
      </td>
      <td>
        <label style="display:flex; align-items:center; justify-content:center; margin:0;">
          <input type="checkbox" data-generated-index="${index}" data-generated-field="given" ${row.given ? 'checked' : ''}>
        </label>
      </td>
      <td>${row.used_count || 0}</td>
      <td>${escapeHtml(formatUnixTimestamp(row.created_at))}</td>
      <td style="display:flex; gap:8px; flex-wrap:wrap;">
        <button class="secondary" type="button" data-generated-copy="${index}">Copy</button>
        <button class="secondary" type="button" data-generated-delete="${index}">Delete</button>
      </td>
    </tr>
  `).join('');

  generatedRowsBody.querySelectorAll('input[data-generated-field="professor"]').forEach((input) => {
    const idx = Number(input.getAttribute('data-generated-index'));
    const row = generatedCodeRows[idx];
    if (!row) return;
    let lastSaved = row.professor || '';
    const commit = async () => {
      const professor = input.value.trim();
      if (professor === lastSaved) return; // nothing changed since the last save
      try {
        await api('/api/admin/generated-codes/update-professor', {
          method: 'POST',
          body: JSON.stringify({ code: row.code, professor }),
        });
        lastSaved = professor;
        row.professor = professor;
        generatedCodesError.textContent = '';
      } catch (error) {
        input.value = lastSaved; // revert on failure, matches the "given" checkbox's behavior
        generatedCodesError.textContent = error.message;
        showToast(error.message);
      }
    };
    input.addEventListener('blur', commit);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        input.blur(); // triggers the 'blur' listener above
      }
    });
  });

  generatedRowsBody.querySelectorAll('select[data-generated-field="study"]').forEach((select) => {
    const idx = Number(select.getAttribute('data-generated-index'));
    if (!Number.isNaN(idx) && generatedCodeRows[idx]) {
      select.value = generatedCodeRows[idx].study_code || '';
    }
    select.addEventListener('change', async () => {
      const code = generatedCodeRows[idx] ? generatedCodeRows[idx].code : '';
      const studyCode = select.value;
      if (!code || !studyCode) {
        return;
      }
      try {
        await api('/api/admin/generated-codes/update-study', {
          method: 'POST',
          body: JSON.stringify({ code, study_code: studyCode }),
        });
        if (generatedCodeRows[idx]) {
          generatedCodeRows[idx].study_code = studyCode;
        }
        renderGeneratedStudyStats();
        generatedCodesError.textContent = '';
        showToast(`Updated ${code}`);
      } catch (error) {
        generatedCodesError.textContent = error.message;
        showToast(error.message);
      }
    });
  });

  generatedRowsBody.querySelectorAll('input[data-generated-field="given"]').forEach((checkbox) => {
    checkbox.addEventListener('change', async () => {
      const idx = Number(checkbox.getAttribute('data-generated-index'));
      const row = generatedCodeRows[idx];
      if (!row || !row.code) {
        return;
      }
      const nextGiven = checkbox.checked;
      try {
        await api('/api/admin/generated-codes/update-given', {
          method: 'POST',
          body: JSON.stringify({ code: row.code, given: nextGiven }),
        });
        row.given = nextGiven;
        generatedCodesError.textContent = '';
      } catch (error) {
        checkbox.checked = !nextGiven;
        generatedCodesError.textContent = error.message;
        showToast(error.message);
      }
    });
  });

  generatedRowsBody.querySelectorAll('button[data-generated-delete]').forEach((button) => {
    button.addEventListener('click', async () => {
      const idx = Number(button.getAttribute('data-generated-delete'));
      const row = generatedCodeRows[idx];
      if (!row) {
        return;
      }
      try {
        await api('/api/admin/generated-codes/delete', {
          method: 'POST',
          body: JSON.stringify({ code: row.code }),
        });
        generatedCodeRows.splice(idx, 1);
        renderGeneratedCodeRows();
        generatedCodesError.textContent = '';
        showToast(`Deleted ${row.code}`);
      } catch (error) {
        generatedCodesError.textContent = error.message;
        showToast(error.message);
      }
    });
  });

  generatedRowsBody.querySelectorAll('button[data-generated-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const idx = Number(button.getAttribute('data-generated-copy'));
      const row = generatedCodeRows[idx];
      if (!row || !row.code) {
        return;
      }
      try {
        await copyTextToClipboard(row.code);
        generatedCodesError.textContent = '';
        showToast(`Copied ${row.code}`);
      } catch (_error) {
        generatedCodesError.textContent = 'Unable to copy automatically. Please copy manually.';
        showToast('Copy failed');
      }
    });
  });
}

function renderGeneratedStudyStats() {
  if (!generatedCodeRows.length) {
    generatedStudyStats.textContent = 'Created codes by study: none yet.';
    return;
  }

  const counts = {};
  for (const row of generatedCodeRows) {
    const studyCode = (row.study_code || '').trim() || '(unassigned)';
    counts[studyCode] = (counts[studyCode] || 0) + 1;
  }

  const parts = Object.entries(counts)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([studyCode, count]) => `${studyCode}: ${count}`);
  generatedStudyStats.textContent = `Created codes by study (${generatedCodeRows.length} total): ${parts.join(' | ')}`;
}

async function copyTextToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const input = document.createElement('input');
  input.value = text;
  input.style.position = 'fixed';
  input.style.left = '-9999px';
  document.body.appendChild(input);
  input.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } finally {
    document.body.removeChild(input);
  }
  if (!ok) {
    throw new Error('copy-failed');
  }
}

function escapeCsvValue(value) {
  const text = String(value == null ? '' : value);
  return `"${text.replace(/"/g, '""')}"`;
}

function exportGeneratedCodesCsv() {
  if (!generatedCodeRows.length) {
    generatedCodesError.textContent = 'No generated codes to export.';
    showToast('Nothing to export');
    return;
  }

  const header = ['code', 'study_code', 'professor', 'given', 'used_count', 'created_at', 'last_used_at'];
  const lines = [header.join(',')];
  for (const row of generatedCodeRows) {
    const cols = [
      row.code,
      row.study_code,
      row.professor || '',
      row.given ? 'yes' : 'no',
      row.used_count || 0,
      formatUnixTimestamp(row.created_at),
      formatUnixTimestamp(row.last_used_at),
    ];
    lines.push(cols.map(escapeCsvValue).join(','));
  }

  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const stamp = new Date().toISOString().replace(/:/g, '-');
  link.href = url;
  link.download = `generated-codes-${stamp}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  generatedCodesError.textContent = '';
  showToast('CSV exported');
}

function buildInstanceUrl(item) {
  const rawUrl = item && item.public_url ? String(item.public_url) : '';
  if (!rawUrl) {
    return '';
  }
  const url = new URL(rawUrl, window.location.origin);
  const token = item && item.token ? String(item.token) : '';
  if (token && !url.searchParams.get('token')) {
    url.searchParams.set('token', token);
  }
  return url.toString();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderAccessCodeRows() {
  if (!accessCodeRows.length) {
    accessCodeRowsBody.innerHTML = '<tr><td colspan="4" class="footnote">No rows yet. Click Add row.</td></tr>';
    return;
  }

  accessCodeRowsBody.innerHTML = accessCodeRows.map((row, index) => `
    <tr>
      <td><input data-index="${index}" data-field="code" value="${escapeHtml(row.code)}" placeholder="Your access code"></td>
      <td style="display:flex; gap:8px; align-items:center;">
        <input data-index="${index}" data-field="template" value="${escapeHtml(row.template)}" placeholder="A new file will be created" style="flex:1;">
        <button class="secondary" type="button" data-upload-index="${index}">Upload</button>
      </td>
      <td>
        <div data-flag-tags="${index}" style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:6px;">
          ${MANDATORY_INSTANCE_FLAGS.map((f) => `
            <span class="flag-tag flag-tag-locked" title="${escapeHtml(f.hint)} (always on for a study code)">${escapeHtml(f.key)} 🔒</span>
          `).join('')}
          ${row.flags.filter((f) => !MANDATORY_INSTANCE_FLAG_KEYS.includes(f)).map((f) => `
            <span class="flag-tag">${escapeHtml(f)}<button type="button" class="flag-tag-remove" data-index="${index}" data-remove-flag="${escapeHtml(f)}" aria-label="Remove ${escapeHtml(f)}">&times;</button></span>
          `).join('')}
        </div>
        <div style="display:flex; gap:6px;">
          <input data-index="${index}" data-flag-input placeholder="e.g. logview, print-all, debug" style="flex:1;">
          <button class="secondary" type="button" data-add-flag="${index}">Add</button>
        </div>
      </td>
      <td><button class="secondary" type="button" data-remove-index="${index}">Remove</button></td>
    </tr>
  `).join('');

  accessCodeRowsBody.querySelectorAll('input[data-field]').forEach((input) => {
    input.addEventListener('input', (event) => {
      const idx = Number(event.target.getAttribute('data-index'));
      const field = event.target.getAttribute('data-field');
      if (!Number.isNaN(idx) && accessCodeRows[idx]) {
        accessCodeRows[idx][field] = event.target.value;
      }
    });
  });

  // Adding a flag: the mandatory tags have no remove button (they are not
  // in this query), so this only ever touches an admin-typed extra.
  const addFlagFromInput = (idx) => {
    const row = accessCodeRows[idx];
    const input = accessCodeRowsBody.querySelector(`input[data-flag-input][data-index="${idx}"]`);
    if (!row || !input) return;
    const flag = normalizeFlagText(input.value);
    if (!flag) return;
    row.flags = withMandatoryFlags([...row.flags, flag]);
    renderAccessCodeRows();
  };

  accessCodeRowsBody.querySelectorAll('button[data-add-flag]').forEach((button) => {
    button.addEventListener('click', () => addFlagFromInput(Number(button.getAttribute('data-add-flag'))));
  });

  accessCodeRowsBody.querySelectorAll('input[data-flag-input]').forEach((input) => {
    input.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      addFlagFromInput(Number(event.target.getAttribute('data-index')));
    });
  });

  accessCodeRowsBody.querySelectorAll('button[data-remove-flag]').forEach((button) => {
    button.addEventListener('click', () => {
      const idx = Number(button.getAttribute('data-index'));
      const flag = button.getAttribute('data-remove-flag');
      const row = accessCodeRows[idx];
      if (Number.isNaN(idx) || !row) return;
      row.flags = row.flags.filter((f) => f !== flag);
      renderAccessCodeRows();
    });
  });

  accessCodeRowsBody.querySelectorAll('button[data-remove-index]').forEach((button) => {
    button.addEventListener('click', () => {
      const idx = Number(button.getAttribute('data-remove-index'));
      if (!Number.isNaN(idx)) {
        accessCodeRows.splice(idx, 1);
        renderAccessCodeRows();
      }
    });
  });

  accessCodeRowsBody.querySelectorAll('button[data-upload-index]').forEach((button) => {
    button.addEventListener('click', () => {
      const idx = Number(button.getAttribute('data-upload-index'));
      if (Number.isNaN(idx) || !accessCodeRows[idx]) return;
      // Create a temporary file input
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.plnb,.json,.md,.txt,.zip';
      input.addEventListener('change', async () => {
        const file = input.files && input.files[0];
        if (!file) return;
        button.disabled = true;
        const prevText = button.textContent;
        button.textContent = 'Uploading...';
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 30000);
          const form = new FormData();
          form.append('file', file, file.name);
          const resp = await fetch('/api/admin/templates/upload', {
            method: 'POST',
            body: form,
            signal: controller.signal,
          });
          clearTimeout(timer);
          if (!resp.ok) {
            const txt = await resp.text();
            throw new Error(txt || `Upload failed (${resp.status})`);
          }
          const payload = await resp.json();
          const location = payload.location || '';
          accessCodeRows[idx].template = location;
          // update the input field value in DOM
          const templateInput = accessCodeRowsBody.querySelector(`input[data-index="${idx}"][data-field="template"]`);
          if (templateInput) templateInput.value = location;
          showToast('Template uploaded');
        } catch (err) {
          showToast(err.message || 'Upload failed');
        } finally {
          button.disabled = false;
          button.textContent = prevText;
        }
      });
      // trigger file picker
      document.body.appendChild(input);
      input.style.display = 'none';
      input.click();
      // cleanup after a short delay
      setTimeout(() => { try { document.body.removeChild(input); } catch (_) {} }, 60000);
    });
  });
}

function normalizeAccessCodeRows(rawJson) {
  let parsed;
  try {
    parsed = JSON.parse(rawJson || '{}');
  } catch (_error) {
    parsed = {};
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return [];
  }
  return Object.entries(parsed).map(([code, value]) => {
    let template = '';
    let flags = null;
    if (typeof value === 'string') {
      template = value;
    } else if (value && typeof value === 'object') {
      for (const key of ['template', 'template_uri', 'template_url', 'location', 'source']) {
        if (typeof value[key] === 'string') {
          template = value[key];
          break;
        }
      }
      if (Array.isArray(value.flags)) {
        // Free text, not checked against a fixed list -- withMandatoryFlags
        // below still normalizes/dedupes each entry and puts user-study/log
        // first, but any other string is accepted and carried through as-is.
        flags = value.flags;
      }
    }
    // No "flags" key at all (a bare template string, or a dict that predates
    // this feature): fall back to DEFAULT_INSTANCE_FLAGS, matching
    // get_instance_flags_for_code in app.py. Either way, route through
    // withMandatoryFlags: a present-but-incomplete "flags" list (hand-edited,
    // or saved before this feature existed) must not render as if
    // user-study/log had been deliberately turned off.
    return { code, template, flags: withMandatoryFlags(flags === null ? DEFAULT_INSTANCE_FLAGS : flags) };
  }).sort((a, b) => a.code.localeCompare(b.code));
}

function openAccessCodeModal() {
  accessCodesModal.classList.add('open');
  accessCodesError.textContent = '';
  generatedCodesError.textContent = '';
  switchAccessModalTab('study');
  reloadAccessCodeRows();
  loadGeneratedCodes();
}

function closeAccessCodeModal() {
  accessCodesModal.classList.remove('open');
}

function addAccessCodeRow() {
  accessCodeRows.push({ code: '', template: '', flags: [...DEFAULT_INSTANCE_FLAGS] });
  renderAccessCodeRows();
}

accessCodesModal.addEventListener('click', (event) => {
  if (event.target === accessCodesModal) {
    closeAccessCodeModal();
  }
});
function showToast(message) {
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('visible'), 2400);
}

async function api(path, options, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      ...options,
    });

    const contentType = response.headers.get('content-type') || '';
    let payload;
    if (contentType.includes('application/json')) {
      payload = await response.json();
    } else {
      payload = await response.text();
    }

    if (!response.ok) {
      const message = typeof payload === 'object' && payload !== null
        ? (payload.error || payload.message || `Request failed (${response.status})`)
        : `Request failed (${response.status})`;
      if (response.status === 401) {
        window.location.href = '/admin/login';
      }
      throw new Error(message);
    }

    return typeof payload === 'object' && payload !== null ? payload : {};
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error(`Request timed out: ${path}`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function loadAccessCodes() {
  accessCodesStatus.textContent = 'Loading access code document...';
  try {
    const payload = await api('/api/admin/access-codes');
    accessCodeRows = normalizeAccessCodeRows(payload.raw_json || '{}\n');
    renderAccessCodeRows();
    accessCodesStatus.textContent = 'Access code document loaded.';
  } catch (error) {
    accessCodesStatus.textContent = `Access code document unavailable: ${error.message}`;
    showToast(error.message);
  }
}

async function loadStudyCodes() {
  const payload = await api('/api/admin/study-codes');
  studyCodes = Array.isArray(payload.studies) ? payload.studies : [];
  renderStudyOptions();
}

async function loadGeneratedCodes() {
  generatedCodesError.textContent = '';
  try {
    const payload = await api('/api/admin/generated-codes');
    generatedCodeRows = Array.isArray(payload.items) ? payload.items : [];
    renderGeneratedCodeRows();
  } catch (error) {
    generatedCodeRows = [];
    renderGeneratedCodeRows();
    generatedCodesError.textContent = error.message;
    showToast(error.message);
  }
}

async function reloadGeneratedCodes() {
  await Promise.all([loadStudyCodes(), loadGeneratedCodes()]);
}

async function generateCodes() {
  const studyCode = generatedStudySelect.value;
  const count = Number(generatedCountInput.value || '1');
  if (!studyCode) {
    generatedCodesError.textContent = 'Choose a study code first.';
    return;
  }
  if (!Number.isInteger(count) || count < 1 || count > 100) {
    generatedCodesError.textContent = 'Count must be between 1 and 100.';
    return;
  }

  generateCodesBtn.disabled = true;
  const prevText = generateCodesBtn.textContent;
  generateCodesBtn.textContent = 'Generating...';
  const professor = generatedProfessorInput.value.trim();
  try {
    const payload = await api('/api/admin/generated-codes/generate', {
      method: 'POST',
      body: JSON.stringify({ study_code: studyCode, count, professor }),
    });
    generatedCodesError.textContent = '';
    const createdCount = Array.isArray(payload.created_codes) ? payload.created_codes.length : 0;
    showToast(`Generated ${createdCount} code(s)`);
    await loadGeneratedCodes();
  } catch (error) {
    generatedCodesError.textContent = error.message;
    showToast(error.message);
  } finally {
    generateCodesBtn.disabled = false;
    generateCodesBtn.textContent = prevText;
  }
}

async function reloadAccessCodeRows() {
  await Promise.all([loadAccessCodes(), loadStudyCodes()]);
}

async function saveAccessCodes() {
  const configObject = {};
  const seenCodes = new Set();
  for (const row of accessCodeRows) {
    const code = row.code.trim();
    const template = row.template.trim();
    if (!code) {
      continue;
    }
    if (seenCodes.has(code)) {
      const message = `Duplicate access code: ${code}`;
      accessCodesError.textContent = message;
      showToast(message);
      return;
    }
    seenCodes.add(code);
    // withMandatoryFlags puts user-study/log first and unions them back in,
    // so the saved JSON can never end up missing them even if row.flags
    // somehow lost track of one.
    configObject[code] = { template: template || null, flags: withMandatoryFlags(row.flags) };
  }

  if (!Object.keys(configObject).length) {
    const message = 'Add at least one access code before saving.';
    accessCodesError.textContent = message;
    showToast(message);
    return;
  }

  accessCodesError.textContent = '';
  saveAccessCodesBtn.disabled = true;
  saveAccessCodesBtn.textContent = 'Saving...';
  try {
    const payload = await api('/api/admin/access-codes', {
      method: 'POST',
      body: JSON.stringify({ raw_json: JSON.stringify(configObject, null, 2) }),
    });
    accessCodeRows = normalizeAccessCodeRows(payload.raw_json || '{}\n');
    renderAccessCodeRows();
    accessCodesStatus.textContent = `Saved ${payload.count} access code(s).`;
    showToast('Access codes saved');
  } catch (error) {
    accessCodesError.textContent = error.message;
    showToast(error.message);
  } finally {
    saveAccessCodesBtn.disabled = false;
    saveAccessCodesBtn.textContent = 'Save';
  }
}

function statusClass(status) {
  if (status === 'running') return 'running';
  if (status === 'starting') return 'starting';
  return 'exited';
}

const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

function formatLastActive(value) {
  if (!value) return '-';
  const timestampMs = value * 1000;
  const diffSeconds = Math.round((Date.now() - timestampMs) / 1000);
  if (!Number.isFinite(diffSeconds)) return '-';
  const absSeconds = Math.abs(diffSeconds);
  if (absSeconds < 60) {
    return relativeTimeFormatter.format(-diffSeconds, 'second');
  }
  const diffMinutes = Math.round(diffSeconds / 60);
  if (Math.abs(diffMinutes) < 60) {
    return relativeTimeFormatter.format(-diffMinutes, 'minute');
  }
  const diffHours = Math.round(diffMinutes / 60);
  if (Math.abs(diffHours) < 24) {
    return relativeTimeFormatter.format(-diffHours, 'hour');
  }
  const diffDays = Math.round(diffHours / 24);
  return relativeTimeFormatter.format(-diffDays, 'day');
}

function renderCards(items) {
  cards.innerHTML = '';
  if (!items.length) {
    cards.innerHTML = '<div class="empty">No plainbook instances yet. Start one to create its own session and UI.</div>';
    return;
  }

  for (const item of items) {
    const displayUrl = buildInstanceUrl(item);
    const card = document.createElement('article');
    card.className = 'card';
    card.innerHTML = `
      <div>
        <h3>${item.id}</h3>
        <div class="meta">Notebook: ${item.notebook_path}</div>
        <div class="meta">Started: ${item.created_at_label}</div>
        <div class="meta">Last active: ${formatRelativeTime(item.last_activity)}</div>
        <div class="meta">Code: ${item.launch_code || '-'}</div>
        <div class="meta">Study: ${item.study_code || '-'}</div>
        
        ${item.exit_code !== null ? `<div class="meta">Exit code: ${item.exit_code}</div>` : ''}
      </div>
      <div>
        <div class="status ${statusClass(item.status || 'starting')}">${item.status || 'starting'}</div>
        <div class="meta" style="margin-top: 8px;">${displayUrl || 'Waiting for plainbook to print its URL...'}</div>
      </div>
      <div class="actions">
        <button class="secondary" ${item.public_url ? '' : 'disabled'} data-open="${item.id}">Open</button>
        <button class="secondary" data-stop="${item.id}" data-backend-ref="${item.backend_ref || ''}">Stop</button>
      </div>
    `;
    cards.appendChild(card);
  }

  cards.querySelectorAll('[data-open]').forEach((button) => {
    button.addEventListener('click', () => {
      const item = items.find((row) => row.id === button.getAttribute('data-open'));
      if (item && item.public_url) {
        const targetUrl = buildInstanceUrl(item);
        if (targetUrl) {
          window.location.replace(targetUrl);
        }
      }
    });
  });

  cards.querySelectorAll('[data-stop]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        const backendRef = button.getAttribute('data-backend-ref') || '';
        await api(`/api/sessions/${button.getAttribute('data-stop')}/stop`, {
          method: 'POST',
          body: JSON.stringify({ backend_ref: backendRef }),
        });
        showToast('Stopped instance');
        await refreshSessions();
      } catch (error) {
        showToast(error.message);
      }
    });
  });
}

async function refreshSessions() {
  try {
    const [payload, usagePayload] = await Promise.all([
      api('/api/sessions'),
      api('/api/admin/usage'),
    ]);
    const items = payload.sessions || [];
    renderCards(items);
    statTotal.textContent = String(items.length);
    statRunning.textContent = String(items.filter((item) => item.status === 'running' || item.status === 'starting').length);
    lastRefresh.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    if (usagePayload && usagePayload.mux) {
      systemUsage.textContent = `Mux usage: PID ${usagePayload.mux.pid} · CPU ${usagePayload.mux.cpu_percent}% · RAM ${usagePayload.mux.memory_mb} MB`;
    } else {
      systemUsage.textContent = 'Mux usage: unavailable';
    }
    if (usagePayload && usagePayload.total) {
      totalUsage.textContent = `Total usage: CPU ${usagePayload.total.cpu_percent}% · RAM ${usagePayload.total.memory_mb} MB`;
    } else {
      totalUsage.textContent = 'Total usage: unavailable';
    }
    if (usagePayload && usagePayload.runtime) {
      runtimeSizeText.textContent = `Runtime folder size: ${usagePayload.runtime.megabytes} MB (${usagePayload.runtime.bytes} bytes)`;
      deleteRuntimeBtn.disabled = !usagePayload.can_delete_runtime;
      deleteRuntimeBtn.title = usagePayload.can_delete_runtime ? 'Delete all files in runtime/' : 'Stop all running instances before deleting runtime files';
    } else {
      runtimeSizeText.textContent = 'Runtime folder size: unavailable';
      deleteRuntimeBtn.disabled = true;
      deleteRuntimeBtn.title = 'Runtime status unavailable';
    }
    stopAllBtn.disabled = items.length === 0;
    if (items.length) {
      launchCommand.textContent = `Latest launch: ${buildInstanceUrl(items[0]) || 'starting...'}`;
    } else {
      launchCommand.textContent = 'Latest launch: none';
    }
  } catch (error) {
    lastRefresh.textContent = 'Update failed';
    systemUsage.textContent = 'Mux usage: unavailable';
    totalUsage.textContent = 'Total usage: unavailable';
    runtimeSizeText.textContent = 'Runtime folder size: unavailable';
    showToast(error.message);
  }
}

async function stopAllInstances() {
  const confirmed = window.confirm('Stop all will stop every current plainbook instance. Continue?');
  if (!confirmed) {
    return;
  }
  stopAllBtn.disabled = true;
  stopAllBtn.textContent = 'Stopping...';
  try {
    const payload = await api('/api/admin/stop-all', { method: 'POST', body: '{}' });
    showToast(`Stopped ${payload.stopped_instances} instance(s)`);
    await refreshSessions();
  } catch (error) {
    showToast(error.message);
  } finally {
    stopAllBtn.disabled = false;
    stopAllBtn.textContent = 'Stop all';
  }
}

async function deleteRuntimeFiles() {
  const confirmed = window.confirm('Delete all files inside runtime/? This only works when no instances are running. Continue?');
  if (!confirmed) {
    return;
  }
  deleteRuntimeBtn.disabled = true;
  deleteRuntimeBtn.textContent = 'Deleting...';
  try {
    const payload = await api('/api/admin/delete-runtime-files', { method: 'POST', body: '{}' });
    showToast(`Deleted ${payload.deleted_files} file(s)`);
    await refreshSessions();
  } catch (error) {
    showToast(error.message);
  } finally {
    deleteRuntimeBtn.disabled = false;
    deleteRuntimeBtn.textContent = 'Delete runtime files';
  }
}

loadAccessCodes();
loadStudyCodes();
refreshSessions();
setInterval(refreshSessions, 3000);
