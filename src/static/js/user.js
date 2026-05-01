const statusBox = document.getElementById('status');
const startBtn = document.getElementById('start-btn');
const codeInput = document.getElementById('launch-code');
let launchInProgress = false;
const INSTANCE_READY_TIMEOUT_SECONDS = 60; // 60 seconds timeout for instance to be ready

function buildLaunchUrl(payload) {
  const rawUrl = String(payload?.public_url || '');
  if (!rawUrl) {
    return '';
  }
  const url = new URL(rawUrl, globalThis.location?.origin || 'http://localhost');
  const token = String(payload?.token || '');
  if (token && !url.searchParams.get('token')) {
    url.searchParams.set('token', token);
  }
  return url.toString();
}

function setStatus(message) {
  statusBox.textContent = message;
}

function openLaunchTarget(targetUrl) {
  const openedWindow = globalThis.open(targetUrl, '_blank', 'noopener,noreferrer');
  setStatus(openedWindow ? 'Instance ready. Opened in a new tab.' : `Instance ready. Open it here: ${targetUrl}`);
}

function getLaunchErrorMessage(error) {
  return String(error?.message || 'Launch failed');
}

async function pollInstanceReady(instanceId, maxWaitSeconds = INSTANCE_READY_TIMEOUT_SECONDS) {
  const pollIntervalMs = 1000; // Poll every 1 second
  const maxAttempts = Math.ceil((maxWaitSeconds * 1000) / pollIntervalMs);
  let attempts = 0;

  while (attempts < maxAttempts) {
    attempts++;
    try {
      const response = await fetch(`/api/instance-status/${instanceId}`, {
        method: 'GET',
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        // Instance not found or other error, keep polling
        const progress = Math.round((attempts / maxAttempts) * 100);
        setStatus(`Starting instance... ${progress}%`);
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
        continue;
      }
      
      const instance = data;
      
      if (instance.public_url && instance.status === 'running') {
        return instance;
      }
      
      if (instance.status === 'exited') {
        throw new Error(`Instance failed to start: ${instance.last_output || 'Unknown error'}`);
      }
      
      // Instance not ready yet, show progress and retry
      const elapsedSeconds = Math.round((attempts * pollIntervalMs) / 1000);
      setStatus(`Starting instance... ${elapsedSeconds}s elapsed`);
      await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
    } catch (error) {
      if (!error.message.includes('Instance failed')) {
        // Network error or other transient error, retry
        const elapsedSeconds = Math.round((attempts * pollIntervalMs) / 1000);
        setStatus(`Starting instance... ${elapsedSeconds}s elapsed`);
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
        continue;
      }
      throw error;
    }
  }
  
  throw new Error('Instance startup timed out. Please try again.');
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
    
    // Handle non-blocking response (status="starting", public_url=null)
    if (payload.status === 'starting' && !payload.public_url) {
      setStatus('Instance is provisioning, waiting for it to be ready...');
      const readyInstance = await pollInstanceReady(payload.id);
      const targetUrl = buildLaunchUrl(readyInstance);
      setStatus('Instance ready! Opening...');
      openLaunchTarget(targetUrl);
    } else {
      // Handle immediate response (legacy or other backends)
      const targetUrl = buildLaunchUrl(payload);
      if (!targetUrl) {
        throw new Error('Instance is still starting. Please try again shortly.');
      }
      openLaunchTarget(targetUrl);
    }
  } catch (error) {
    const rawMessage = getLaunchErrorMessage(error);
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
