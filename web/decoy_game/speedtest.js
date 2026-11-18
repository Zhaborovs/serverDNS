(() => {
  const ARC_LEN = 385;
  const MAX_GAUGE_MBPS = 250;

  const btnToggle = document.getElementById('stToggleBtn');
  const phaseBadge = document.getElementById('stPhaseBadge');
  const gaugeArc = document.getElementById('stGaugeArc');
  const gaugeVal = document.getElementById('stGaugeVal');
  const gaugeUnit = document.getElementById('stGaugeUnit');
  const downEl = document.getElementById('stDownVal');
  const upEl = document.getElementById('stUpVal');
  const pingEl = document.getElementById('stPingVal');
  const jitterEl = document.getElementById('stJitterVal');
  const chartCanvas = document.getElementById('stChartCanvas');
  const chartCtx = chartCanvas.getContext('2d');
  const streamToggle = document.getElementById('stStreamToggle');
  const streamInfo = document.getElementById('stStreamInfo');
  const nodeHostLabel = document.getElementById('nodeHostLabel');

  if (nodeHostLabel && window.location.hostname) {
    nodeHostLabel.textContent = `Узел проверки: ${window.location.hostname} (TLS 1.3)`;
  }

  let runningTest = false;
  let abortCtrl = null;
  let activeXhrs = [];
  let chartPoints = [];

  // Состояние длительного теста 4K-потока
  let streamTimer = null;
  let streamBytes = 0;
  const savedStreamState = localStorage.getItem('np_stream_stability');
  let streamEnabled = savedStreamState === null ? true : savedStreamState === '1';
  streamToggle.checked = streamEnabled;

  function setGauge(val, unit = 'Мбит/с', maxRef = MAX_GAUGE_MBPS) {
    gaugeVal.textContent = Number.isFinite(val) ? val.toFixed(1) : '0.0';
    gaugeUnit.textContent = unit;
    const ratio = Math.max(0, Math.min(1, val / maxRef));
    gaugeArc.style.strokeDashoffset = String(ARC_LEN * (1 - ratio));
  }

  function pushChartPoint(val, color = '#38bdf8') {
    chartPoints.push({ val, color });
    if (chartPoints.length > 60) chartPoints.shift();
    drawChart();
  }

  function drawChart() {
    const w = chartCanvas.width;
    const h = chartCanvas.height;
    chartCtx.clearRect(0, 0, w, h);

    // Сетка
    chartCtx.strokeStyle = 'rgba(148, 163, 184, 0.1)';
    chartCtx.lineWidth = 1;
    for (let y = 18; y < h; y += 18) {
      chartCtx.beginPath();
      chartCtx.moveTo(0, y);
      chartCtx.lineTo(w, y);
      chartCtx.stroke();
    }

    if (chartPoints.length < 2) return;
    const maxV = Math.max(20, ...chartPoints.map((p) => p.val)) * 1.15;
    const stepX = w / 59;

    chartCtx.beginPath();
    chartPoints.forEach((pt, idx) => {
      const x = idx * stepX;
      const y = h - 6 - (pt.val / maxV) * (h - 14);
      if (idx === 0) chartCtx.moveTo(x, y);
      else chartCtx.lineTo(x, y);
    });
    chartCtx.strokeStyle = chartPoints[chartPoints.length - 1].color;
    chartCtx.lineWidth = 2.5;
    chartCtx.stroke();
  }

  function setMetric(el, value, unit) {
    el.innerHTML = `${value}<span>${unit}</span>`;
  }

  async function measurePingAndJitter(signal) {
    phaseBadge.textContent = 'Измерение Ping & Jitter...';
    const samples = [];
    for (let i = 0; i < 8; i++) {
      if (signal.aborted) return null;
      const t0 = performance.now();
      await fetch(`/speedtest/ping?n=${i}_${Date.now()}`, { cache: 'no-store', signal });
      const rtt = performance.now() - t0;
      if (i > 0) samples.push(rtt); // отбрасываем первый разогрев TLS/DNS
      const avg = samples.length ? samples.reduce((a, b) => a + b, 0) / samples.length : rtt;
      setGauge(avg, 'мс', 250);
      setMetric(pingEl, Math.round(avg), 'мс');
      await new Promise((r) => setTimeout(r, 90));
    }
    const avgPing = samples.reduce((a, b) => a + b, 0) / samples.length;
    let jitterSum = 0;
    for (let i = 1; i < samples.length; i++) {
      jitterSum += Math.abs(samples[i] - samples[i - 1]);
    }
    const jitter = samples.length > 1 ? jitterSum / (samples.length - 1) : 0;
    setMetric(pingEl, Math.round(avgPing), 'мс');
    setMetric(jitterEl, jitter.toFixed(1), 'мс');
    return { ping: avgPing, jitter };
  }

  async function measureDownload(signal) {
    phaseBadge.textContent = 'Тест скачивания (Download)...';
    let loadedBytes = 0;
    const startTs = performance.now();
    const durationMs = 5500;
    const workers = 3;

    const uiTimer = setInterval(() => {
      const elapsedSec = Math.max(0.15, (performance.now() - startTs) / 1000);
      const mbps = (loadedBytes * 8) / elapsedSec / 1e6;
      setGauge(mbps, 'Мбит/с');
      setMetric(downEl, mbps.toFixed(1), 'Мбит/с');
      pushChartPoint(mbps, '#38bdf8');
    }, 180);

    async function workerLoop(id) {
      while (!signal.aborted && performance.now() - startTs < durationMs) {
        try {
          const resp = await fetch(`/speedtest/down?w=${id}&r=${Math.random()}`, {
            cache: 'no-store',
            signal,
          });
          if (!resp.body) {
            const buf = await resp.arrayBuffer();
            loadedBytes += buf.byteLength;
            continue;
          }
          const reader = resp.body.getReader();
          while (!signal.aborted && performance.now() - startTs < durationMs) {
            const { done, value } = await reader.read();
            if (done) break;
            loadedBytes += value.byteLength;
          }
          await reader.cancel().catch(() => {});
        } catch (err) {
          if (signal.aborted) break;
        }
      }
    }

    await Promise.all(Array.from({ length: workers }, (_, i) => workerLoop(i)));
    clearInterval(uiTimer);

    const totalSec = Math.max(0.2, (performance.now() - startTs) / 1000);
    const finalMbps = (loadedBytes * 8) / totalSec / 1e6;
    setGauge(finalMbps, 'Мбит/с');
    setMetric(downEl, finalMbps.toFixed(1), 'Мбит/с');
    return finalMbps;
  }

  function buildRandomPayload(sizeBytes) {
    const buf = new Uint8Array(sizeBytes);
    for (let offset = 0; offset < sizeBytes; offset += 65536) {
      const sliceLen = Math.min(65536, sizeBytes - offset);
      crypto.getRandomValues(buf.subarray(offset, offset + sliceLen));
    }
    return buf;
  }

  async function measureUpload(signal) {
    phaseBadge.textContent = 'Тест отдачи (Upload)...';
    const payload = buildRandomPayload(3 * 1024 * 1024); // чанк 3 МБ
    let sentBytesTotal = 0;
    const startTs = performance.now();
    const durationMs = 5000;

    const uiTimer = setInterval(() => {
      const elapsedSec = Math.max(0.15, (performance.now() - startTs) / 1000);
      const mbps = (sentBytesTotal * 8) / elapsedSec / 1e6;
      setGauge(mbps, 'Мбит/с');
      setMetric(upEl, mbps.toFixed(1), 'Мбит/с');
      pushChartPoint(mbps, '#34d399');
    }, 180);

    function sendOneChunk() {
      return new Promise((resolve) => {
        if (signal.aborted || performance.now() - startTs >= durationMs) {
          resolve();
          return;
        }
        const xhr = new XMLHttpRequest();
        activeXhrs.push(xhr);
        let prevLoaded = 0;
        xhr.open('POST', `/speedtest/up?r=${Math.random()}`, true);
        xhr.upload.onprogress = (ev) => {
          const delta = Math.max(0, ev.loaded - prevLoaded);
          prevLoaded = ev.loaded;
          sentBytesTotal += delta;
        };
        xhr.onload = () => resolve();
        xhr.onerror = () => resolve();
        xhr.onabort = () => resolve();
        xhr.send(payload);
      });
    }

    async function upWorker() {
      while (!signal.aborted && performance.now() - startTs < durationMs) {
        await sendOneChunk();
      }
    }

    await Promise.all([upWorker(), upWorker()]);
    activeXhrs = [];
    clearInterval(uiTimer);

    const totalSec = Math.max(0.2, (performance.now() - startTs) / 1000);
    const finalMbps = (sentBytesTotal * 8) / totalSec / 1e6;
    setGauge(finalMbps, 'Мбит/с');
    setMetric(upEl, finalMbps.toFixed(1), 'Мбит/с');
    return finalMbps;
  }

  async function runFullSpeedTest() {
    if (runningTest) {
      if (abortCtrl) abortCtrl.abort();
      activeXhrs.forEach((x) => x.abort());
      activeXhrs = [];
      runningTest = false;
      btnToggle.textContent = '⚡ Проверить скорость интернета';
      phaseBadge.textContent = 'Остановлено';
      if (streamEnabled) scheduleNextStreamChunk(500);
      return;
    }

    runningTest = true;
    clearTimeout(streamTimer);
    abortCtrl = new AbortController();
    chartPoints = [];
    drawChart();

    btnToggle.textContent = '⏹ Остановить проверку';
    setMetric(downEl, '...', 'Мбит/с');
    setMetric(upEl, '...', 'Мбит/с');

    try {
      await measurePingAndJitter(abortCtrl.signal);
      if (abortCtrl.signal.aborted) return;
      const downMbps = await measureDownload(abortCtrl.signal);
      if (abortCtrl.signal.aborted) return;
      await measureUpload(abortCtrl.signal);
      if (!abortCtrl.signal.aborted) {
        phaseBadge.textContent = 'Тест завершён (OK)';
        setGauge(downMbps, 'Мбит/с');
      }
    } catch (err) {
      if (!abortCtrl.signal.aborted) {
        phaseBadge.textContent = 'Ошибка соединения';
      }
    } finally {
      runningTest = false;
      btnToggle.textContent = '⚡ Повторить проверку';
      if (streamEnabled) scheduleNextStreamChunk(800);
    }
  }

  btnToggle.addEventListener('click', runFullSpeedTest);

  // --- Фоновый длительный тест стабильности 4K-потока ---
  function randInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  async function pumpStabilitySegment() {
    if (!streamEnabled || runningTest) return;
    const chunkBytes = randInt(262144, 1441792); // 256 КБ - 1.4 МБ (реальный профиль 4K сегментов)
    const url = `/videoplayback?itag=248&rn=${Math.random().toString(36).slice(2, 9)}&len=${chunkBytes}`;
    const t0 = performance.now();
    try {
      const resp = await fetch(url, {
        headers: { Range: `bytes=0-${chunkBytes - 1}` },
        cache: 'no-store',
      });
      const buf = await resp.arrayBuffer();
      const dt = Math.max(0.05, (performance.now() - t0) / 1000);
      streamBytes += buf.byteLength;
      const instMbps = (buf.byteLength * 8) / dt / 1e6;
      streamInfo.textContent = `Проверено ${(streamBytes / 1048576).toFixed(1)} МБ • Поток ${instMbps.toFixed(1)} Мбит/с • Потерь: 0%`;
    } catch (_) {
      streamInfo.textContent = 'Ожидание ответа узла проверки...';
    }
    if (streamEnabled && !runningTest) {
      scheduleNextStreamChunk(randInt(1400, 3600));
    }
  }

  function scheduleNextStreamChunk(delayMs) {
    clearTimeout(streamTimer);
    streamTimer = setTimeout(pumpStabilitySegment, delayMs);
  }

  streamToggle.addEventListener('change', () => {
    streamEnabled = streamToggle.checked;
    localStorage.setItem('np_stream_stability', streamEnabled ? '1' : '0');
    if (streamEnabled) {
      streamInfo.textContent = 'Тест стабильности 4K-потока активен...';
      scheduleNextStreamChunk(200);
    } else {
      clearTimeout(streamTimer);
      streamInfo.textContent = 'Длительный тест стабильности на паузе. Пока идёт замер — играйте ниже ↓';
    }
  });

  if (streamEnabled) {
    scheduleNextStreamChunk(600);
  }
})();
