const statusBox = document.getElementById('status');
const startBtn = document.getElementById('start-btn');
const codeInput = document.getElementById('launch-code');
let launchInProgress = false;

function buildLaunchUrl(payload) {
  const rawUrl = payload && payload.public_url ? String(payload.public_url) : '';
  if (!rawUrl) {
    return '';
  }
  const url = new URL(rawUrl, window.location.origin);
  const token = payload && payload.token ? String(payload.token) : '';
  if (token && !url.searchParams.get('token')) {
    url.searchParams.set('token', token);
  }
  return url.toString();
}

function setStatus(message) {
  statusBox.textContent = message;
}

async function launchPlainbook() {
  if (launchInProgress) {
    return;
  }
  const code = codeInput.value.trim();
  if (!code) {
    setStatus('Please enter a code first.');
    return;
  }
  launchInProgress = true;
  startBtn.disabled = true;
  startBtn.textContent = 'Launching...';
  setStatus('Starting a new plainbook instance...');
  try {
    const response = await fetch('/api/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json')
      ? await response.json()
      : await response.text();
    if (!response.ok) {
      const message = typeof payload === 'object' && payload !== null
        ? (payload.error || payload.message || 'Launch failed')
        : String(payload || 'Launch failed');
      throw new Error(message);
    }
    if (payload.public_url) {
      const targetUrl = buildLaunchUrl(payload);
      if (!targetUrl) {
        throw new Error('Instance URL unavailable');
      }
      const openedWindow = window.open(targetUrl, '_blank', 'noopener,noreferrer');
      if (openedWindow) {
        setStatus('Instance ready. Opened in a new tab.');
      } else {
        setStatus(`Instance ready. Open it here: ${targetUrl}`);
      }
    } else {
      setStatus('Instance started and is initializing. Please try again shortly.');
    }
  } catch (error) {
    const rawMessage = error && error.message ? String(error.message) : 'Launch failed';
    if (rawMessage.includes('did not match the expected pattern')) {
      setStatus('Access code wrong, please contact the adminitrator');
    } else {
      setStatus(rawMessage);
    }
  } finally {
    startBtn.disabled = false;
    startBtn.textContent = 'Start Plainbook';
    launchInProgress = false;
  }
}
