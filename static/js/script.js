/* ====================================================================
   KAVACHAM AI — Main Application Script
   Handles: page navigation, analysis, Ultra AI, history, settings
   ==================================================================== */

'use strict';

// ---- State ----
let currentPage = 'dashboard';
let currentMode = 'anveshak';
let analysisHistory = [];
let lastAnveshakResult = null;
let lastUltraResult = null;

// ---- Page Navigation ----
function navigateTo(page) {
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  // Deactivate nav
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  // Show target
  const target = document.getElementById('page-' + page);
  if (target) {
    target.classList.remove('hidden', 'page-enter');
    // Restart the entrance choreography
    void target.offsetWidth;
    target.classList.add('page-enter');
    window.setTimeout(() => target.classList.remove('page-enter'), 850);
  }
  // Activate nav item
  const navItem = document.querySelector(`[data-page="${page}"]`);
  if (navItem) navItem.classList.add('active');
  currentPage = page;

  // Close mobile sidebar
  closeSidebar();

  // Reveal freshly-visible elements & resize charts inside the new page
  if (window.AnveshakEffects) window.AnveshakEffects.revealVisible(target);
  if (window.ANVESHAK_CHARTS) window.ANVESHAK_CHARTS.resizeAll();

  // Page-specific init
  if (page === 'dashboard') refreshDashboard();
  if (page === 'history') renderHistoryList();
  if (page === 'performance') {
    if (window.ANVESHAK_CHARTS) window.ANVESHAK_CHARTS.ensurePerformance();
  }
  if (page === 'testsuite') initTestSuite();
  if (page === 'settings') initSettings();
  if (page === 'gmail') initGmailPage();
  if (page === 'phishing') {
    initThreatChecker();
    initPhishingChecker();
  }
}

// ---- Mobile Sidebar ----
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  sidebar.classList.toggle('open');
  overlay.classList.toggle('hidden');
}
function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  sidebar.classList.remove('open');
  overlay.classList.add('hidden');
}

// ---- Analysis Mode ----
function setAnalysisMode(mode) {
  currentMode = mode;
  document.querySelectorAll('.mode-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.mode === mode);
  });
  const desc = document.getElementById('mode-desc-text');
  const ultraNotice = document.getElementById('ultra-privacy-notice');
  if (mode === 'ultra') {
    desc.textContent = 'Ultra AI runs both Kavacham AI (local ML) and Kavacham AI Pro (contextual intelligence) for a comprehensive comparison.';
    ultraNotice.classList.remove('hidden');
  } else {
    desc.textContent = 'Kavacham AI uses your trained ML model for fast, local classification.';
    ultraNotice.classList.add('hidden');
  }
  // Clear previous results
  document.getElementById('result-anveshak').classList.add('hidden');
  document.getElementById('result-ultra').classList.add('hidden');
}

// ---- Toggle Advanced Fields ----
function toggleAdvanced() {
  const body = document.getElementById('advanced-fields');
  body.classList.toggle('hidden');
}

// ---- Run Analysis ----
async function runAnalysis() {
  const body = document.getElementById('input-body').value.trim();
  const subject = document.getElementById('input-subject').value.trim();
  const sender = document.getElementById('input-sender').value.trim();
  const urls = document.getElementById('input-urls').value.trim();

  if (!body && !subject) {
    showToast('Please enter at least an email subject or body.', 'warning');
    return;
  }

  // Hide previous results
  document.getElementById('result-anveshak').classList.add('hidden');
  document.getElementById('result-ultra').classList.add('hidden');

  if (currentMode === 'anveshak') {
    await runAnveshakAnalysis(subject, sender, body, urls);
  } else {
    await runUltraAnalysis(subject, sender, body, urls);
  }
}

// ---- Anveshak AI Mode ----
async function runAnveshakAnalysis(subject, sender, body, urls) {
  showLoading('Analyzing with Kavacham AI...');
  try {
    const response = await fetch('/analyze-email-simple', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, sender, body, urls })
    });
    const data = await response.json();
    hideLoading();

    if (!data.success) {
      showToast('Analysis failed: ' + (data.error || 'Unknown error'), 'error');
      return;
    }

    lastAnveshakResult = data;
    renderAnveshakResult(data);

    // Add to history
    addToHistory({
      sender: sender || '—',
      subject: subject || '(No Subject)',
      classification: data.prediction,
      confidence: data.confidence,
      analysis_mode: 'anveshak',
      result: data
    });

  } catch (err) {
    hideLoading();
    showToast('Network error: ' + err.message, 'error');
  }
}

// ---- Ultra AI Mode ----
async function runUltraAnalysis(subject, sender, body, urls) {
  showLoading('Running Ultra AI analysis (Kavacham AI + Kavacham AI Pro)...');
  try {
    const response = await fetch('/ultra-analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, sender, body, urls })
    });
    const data = await response.json();
    hideLoading();

    if (!data.success) {
      showToast('Analysis failed: ' + (data.error || 'Unknown error'), 'error');
      return;
    }

    lastUltraResult = data;
    renderUltraResult(data);

    // Add to history
    addToHistory({
      sender: sender || '—',
      subject: subject || '(No Subject)',
      classification: data.anveshak.prediction,
      confidence: data.anveshak.confidence,
      analysis_mode: 'ultra',
      result: data
    });

  } catch (err) {
    hideLoading();
    showToast('Network error: ' + err.message, 'error');
  }
}

// ---- Result voice/sound feedback (Kavacham AI) ----
function playResultSound(isSpam) {
  if (!window.SoundFX) return;
  try {
    if (isSpam) window.SoundFX.spam();
    else window.SoundFX.safe();
  } catch (e) { /* audio must never break analysis */ }
}

// ---- Render Anveshak Result ----
function renderAnveshakResult(data) {
  const container = document.getElementById('result-anveshak');
  container.classList.remove('hidden');

  // Verdict card
  const isSpam = data.prediction === 'Spam';
  playResultSound(isSpam);
  const verdictEl = document.getElementById('anveshak-verdict');
  verdictEl.textContent = isSpam ? 'SPAM' : 'NOT SPAM';
  verdictEl.className = 'verdict-value ' + (isSpam ? 'spam' : 'ham');

  document.getElementById('anveshak-confidence').textContent = data.confidence + '%';
  document.getElementById('anveshak-threshold').textContent = 'Threshold: ' + data.decision_threshold + '%';

  const verdictCard = document.getElementById('anveshak-verdict-card');
  verdictCard.style.borderColor = isSpam ? 'rgba(239,68,68,0.35)' : 'rgba(34,197,94,0.3)';

  // Explanation
  const explanation = generateExplanation(data, 'anveshak');
  document.getElementById('anveshak-explanation').textContent = explanation;

  // Probability bars
  const probBars = document.getElementById('anveshak-prob-bars');
  probBars.innerHTML = `
    <div class="prob-bar-row">
      <div class="prob-bar-labels"><span>Spam Probability</span><span>${data.probability_spam}%</span></div>
      <div class="prob-bar-track"><div class="prob-bar-fill spam-bar" style="width:${Math.min(data.probability_spam,100)}%"></div></div>
    </div>
    <div class="prob-bar-row">
      <div class="prob-bar-labels"><span>Ham Probability</span><span>${data.probability_ham}%</span></div>
      <div class="prob-bar-track"><div class="prob-bar-fill ham-bar" style="width:${Math.min(data.probability_ham,100)}%"></div></div>
    </div>
  `;

  // Signals table
  renderSignalsTable(data.influential_signals, 'anveshak-signals-table');

  // Scroll to result
  container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---- Render Ultra Result ----
function renderUltraResult(data) {
  const container = document.getElementById('result-ultra');
  container.classList.remove('hidden');

  const anveshak = data.anveshak;
  const gemini = data.gemini;
  const modelsAgree = data.models_agree;

  // Final verdict — Pro engine (Kavacham AI Pro) takes priority when available.
  const proOk = gemini && gemini.success;
  const finalIsSpam = data.final_verdict != null
    ? data.final_verdict === 'Spam'
    : (proOk ? gemini.classification === 'Spam' : anveshak.prediction === 'Spam');
  const finalSource = data.final_source || (proOk ? 'Kavacham AI Pro' : 'Kavacham AI');
  const finalConfidence = data.final_confidence != null
    ? data.final_confidence
    : (proOk && gemini.confidence != null ? gemini.confidence : anveshak.confidence);
  playResultSound(finalIsSpam);

  // --- Anveshak engine card ---
  const anveshakVerdictEl = document.getElementById('ultra-anveshak-verdict');
  const isSpam = anveshak.prediction === 'Spam';
  anveshakVerdictEl.textContent = isSpam ? 'SPAM' : 'NOT SPAM';
  anveshakVerdictEl.className = 'engine-verdict ' + (isSpam ? 'spam' : 'ham');
  document.getElementById('ultra-anveshak-conf').textContent = anveshak.confidence + '%';

  const anveshakCard = document.getElementById('ultra-anveshak-card');
  anveshakCard.className = 'engine-card ' + (isSpam ? 'spam-border' : 'ham-border');

  // Anveshak signals brief
  const sigBrief = document.getElementById('ultra-anveshak-signals');
  if (anveshak.influential_signals && anveshak.influential_signals.length > 0) {
    sigBrief.innerHTML = anveshak.influential_signals.slice(0, 3).map(s =>
      `<span class="signal-badge ${s.status === 'Spam signal' ? 'spam' : s.status === 'Ham / Safe signal' ? 'ham' : 'neutral'}">${escHtml(s.token)}</span>`
    ).join(' ');
  }

  // --- Gemini engine card ---
  const geminiBody = document.getElementById('ultra-gemini-body');
  const geminiVerdictEl = document.getElementById('ultra-gemini-verdict');

  if (!gemini || !gemini.success) {
    // Gemini failed gracefully
    geminiVerdictEl.textContent = 'UNAVAILABLE';
    geminiVerdictEl.className = 'engine-verdict';
    geminiVerdictEl.style.color = 'var(--text-muted)';
    document.getElementById('ultra-gemini-conf').textContent = '—';
    document.getElementById('ultra-gemini-risk').textContent = '—';

    const failMsg = document.createElement('div');
    failMsg.style.cssText = 'margin-top:10px;font-size:12px;color:var(--yellow);';
    failMsg.textContent = '⚠ Kavacham AI Pro analysis unavailable. Kavacham AI result is still valid.';
    geminiBody.appendChild(failMsg);
  } else {
    const geminiSpam = gemini.classification === 'Spam';
    geminiVerdictEl.textContent = geminiSpam ? 'SPAM' : 'NOT SPAM';
    geminiVerdictEl.className = 'engine-verdict ' + (geminiSpam ? 'spam' : 'ham');
    document.getElementById('ultra-gemini-conf').textContent = gemini.confidence + '%';
    const riskEl = document.getElementById('ultra-gemini-risk');
    riskEl.textContent = gemini.risk_level || '—';
    riskEl.style.color = gemini.risk_level === 'High' ? 'var(--red)' : gemini.risk_level === 'Medium' ? 'var(--yellow)' : 'var(--green)';

    const geminiCard = document.getElementById('ultra-gemini-card');
    geminiCard.className = 'engine-card ' + (geminiSpam ? 'spam-border' : 'ham-border');
  }

  // --- Agreement Banner ---
  const banner = document.getElementById('agreement-banner');
  const bannerIcon = document.getElementById('agreement-icon');
  const bannerText = document.getElementById('agreement-text');

  if (!gemini || !gemini.success) {
    banner.className = 'agreement-banner';
    banner.style.display = 'none';
  } else {
    banner.style.display = '';
    if (modelsAgree) {
      banner.className = 'agreement-banner agree';
      bannerIcon.textContent = '✓';
      bannerText.textContent = 'MODELS AGREE — ' + data.combined_assessment;
      bannerText.className = 'agreement-text agree';
    } else {
      banner.className = 'agreement-banner disagree';
      bannerIcon.textContent = '⚠';
      bannerText.textContent = 'MODELS DISAGREE — ' + data.combined_assessment;
      bannerText.className = 'agreement-text disagree';
    }
  }

  // --- Combined Summary ---
  document.getElementById('combined-summary').textContent = data.combined_assessment || '—';

  // --- Gemini Explanation Detail ---
  const geminiReasoning = document.getElementById('gemini-reasoning');
  if (gemini && gemini.success) {
    geminiReasoning.textContent = gemini.reasoning_summary || '—';

    const geminiDetail = document.getElementById('gemini-signals-detail');
    let detailHtml = '';
    if (gemini.suspicious_signals && gemini.suspicious_signals.length > 0) {
      detailHtml += `<div class="gemini-signals-section"><h4>Suspicious Signals</h4><div class="signal-list">`;
      gemini.suspicious_signals.forEach(s => {
        detailHtml += `<div class="signal-list-item sus">${escHtml(s)}</div>`;
      });
      detailHtml += `</div></div>`;
    }
    if (gemini.legitimate_signals && gemini.legitimate_signals.length > 0) {
      detailHtml += `<div class="gemini-signals-section"><h4>Legitimate Signals</h4><div class="signal-list">`;
      gemini.legitimate_signals.forEach(s => {
        detailHtml += `<div class="signal-list-item leg">${escHtml(s)}</div>`;
      });
      detailHtml += `</div></div>`;
    }
    if (gemini.gemini_note) {
      detailHtml += `<p style="margin-top:12px;font-size:12.5px;color:var(--text-muted);font-style:italic;">${escHtml(gemini.gemini_note)}</p>`;
    }
    geminiDetail.innerHTML = detailHtml;
  } else {
    geminiReasoning.textContent = 'Kavacham AI Pro analysis was not available for this request.';
    document.getElementById('gemini-signals-detail').innerHTML = '';
  }

  // --- Anveshak signals (detail) ---
  renderSignalsTable(anveshak.influential_signals, 'ultra-signals-table');

  // --- Comparison Table ---
  const geminiClass = gemini && gemini.success ? gemini.classification : 'Unavailable';
  const geminiConf = gemini && gemini.success ? gemini.confidence + '%' : '—';
  const geminiReason = gemini && gemini.success ? (gemini.reasoning_summary || '').slice(0, 80) + '...' : 'Kavacham AI Pro unavailable';
  document.getElementById('comparison-table').innerHTML = `
    <thead><tr>
      <th>Signal</th>
      <th>Kavacham AI</th>
      <th>Kavacham AI Pro</th>
    </tr></thead>
    <tbody>
      <tr><td>Classification</td>
          <td><span class="signal-badge ${anveshak.prediction === 'Spam' ? 'spam' : 'ham'}">${escHtml(anveshak.prediction)}</span></td>
          <td><span class="signal-badge ${geminiClass === 'Spam' ? 'spam' : geminiClass === 'Not Spam' ? 'ham' : 'neutral'}">${escHtml(geminiClass)}</span></td></tr>
      <tr><td>Confidence</td><td class="mono">${anveshak.confidence}%</td><td class="mono">${geminiConf}</td></tr>
      <tr><td>Decision Threshold</td><td class="mono">${anveshak.decision_threshold}%</td><td class="mono">Contextual</td></tr>
      <tr><td>Main Reasoning</td>
          <td style="font-size:12px;color:var(--text-secondary);">${generateExplanation(anveshak, 'brief')}</td>
          <td style="font-size:12px;color:var(--text-secondary);">${escHtml(geminiReason)}</td></tr>
      <tr><td>Agreement</td>
          <td colspan="2" style="text-align:center;">
            ${proOk
              ? `<span class="signal-badge ${modelsAgree ? 'ham' : 'spam'}">${modelsAgree ? 'MODELS AGREE' : 'MODELS DISAGREE'}</span>`
              : `<span class="signal-badge neutral">KAVACHAM AI (LOCAL)</span>`}
          </td></tr>
    </tbody>
  `;

  // --- Final Verdict (Pro-priority) ---
  renderFinalVerdict(finalIsSpam, finalSource, finalConfidence);

  container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---- Final Verdict Card ----
function renderFinalVerdict(finalIsSpam, source, confidence) {
  const card = document.getElementById('final-verdict-card');
  if (!card) return;
  const badge = document.getElementById('final-verdict-badge');
  const verdictEl = document.getElementById('final-verdict-text');
  const sourceEl = document.getElementById('final-verdict-source');
  const confEl = document.getElementById('final-verdict-conf');

  if (badge) {
    badge.textContent = source;
    badge.className = 'analysis-mode-badge ' + (source === 'Kavacham AI Pro' ? 'ultra-badge' : 'anveshak-badge');
  }
  if (verdictEl) {
    verdictEl.textContent = finalIsSpam ? 'SPAM DETECTED' : 'SAFE';
    verdictEl.className = 'final-verdict-value ' + (finalIsSpam ? 'spam' : 'ham');
  }
  if (sourceEl) {
    sourceEl.textContent = 'Priority: ' + source;
    sourceEl.className = 'final-verdict-source ' + (source === 'Kavacham AI Pro' ? 'pro' : 'core');
  }
  if (confEl) {
    confEl.textContent = (confidence != null ? confidence : '—') + (confidence != null ? '%' : '');
  }
  card.classList.remove('hidden');
}

// ---- Render Signals Table ----
function renderSignalsTable(signals, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (!signals || signals.length === 0) {
    container.innerHTML = '<p style="font-size:13px;color:var(--text-muted);padding:8px 0;">No influential signals extracted.</p>';
    return;
  }
  const rows = signals.map(s => {
    const cls = s.status === 'Spam signal' ? 'spam' : s.status === 'Ham / Safe signal' ? 'ham' : 'neutral';
    const label = s.status === 'Spam signal' ? 'Spam Signal' : s.status === 'Ham / Safe signal' ? 'Safe Signal' : 'Context-Dependent';
    return `<tr>
      <td><span class="signal-token">${escHtml(s.token)}</span></td>
      <td><span class="signal-badge ${cls}">${label}</span></td>
      <td><span class="signal-score">${s.score > 0 ? '+' : ''}${s.score}</span></td>
    </tr>`;
  }).join('');
  container.innerHTML = `
    <table style="width:100%;border-collapse:collapse;">
      <thead><tr><th style="text-align:left;padding:8px 14px;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border);">Signal / Token</th>
        <th style="text-align:left;padding:8px 14px;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border);">Influence</th>
        <th style="text-align:left;padding:8px 14px;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border);">Score</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

// ---- Generate Explanation Text ----
function generateExplanation(data, mode) {
  const isSpam = data.prediction === 'Spam';
  const signals = data.influential_signals || [];
  const spamSigs = signals.filter(s => s.status === 'Spam signal').map(s => s.token);
  const safeSigs = signals.filter(s => s.status === 'Ham / Safe signal').map(s => s.token);

  if (mode === 'brief') {
    return isSpam
      ? 'Spam-correlated token patterns detected'
      : 'Legitimate communication patterns detected';
  }

  if (isSpam) {
    const tokenList = spamSigs.length > 0
      ? ` Influential spam signals include: ${spamSigs.slice(0, 4).join(', ')}.`
      : '';
    return `Kavacham AI classified this message as Spam because the learned token patterns and feature combinations resemble characteristics frequently found in phishing, promotional, or deceptive messages.${tokenList} The spam probability exceeded the ${data.decision_threshold}% decision threshold.`;
  } else {
    const safeList = safeSigs.length > 0
      ? ` Legitimate contextual signals include: ${safeSigs.slice(0, 3).join(', ')}.`
      : '';
    const topTokens = signals.slice(0, 3).map(s => s.token).join(', ');
    return `Kavacham AI classified this message as Not Spam because it lacks strong spam indicators such as credential requests, suspicious payment instructions, or deceptive calls to action.${safeList} The spam probability (${data.probability_spam}%) remained below the ${data.decision_threshold}% threshold.`;
  }
}

// ---- Clear Analysis ----
function clearAnalysis() {
  document.getElementById('input-body').value = '';
  document.getElementById('input-subject').value = '';
  document.getElementById('input-sender').value = '';
  document.getElementById('input-urls').value = '';
  document.getElementById('result-anveshak').classList.add('hidden');
  document.getElementById('result-ultra').classList.add('hidden');
}

// ---- History ----
function addToHistory(entry) {
  const item = {
    id: generateId(),
    sender: entry.sender,
    subject: entry.subject,
    classification: entry.classification,
    confidence: entry.confidence,
    analysis_mode: entry.analysis_mode,
    timestamp: new Date().toISOString(),
    result: entry.result
  };
  analysisHistory.unshift(item);
  if (analysisHistory.length > 50) analysisHistory = analysisHistory.slice(0, 50);

  // Also push to server session
  fetch('/api/history', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ entry: item })
  }).catch(() => {});

  refreshDashboard();
}

function renderHistoryList() {
  const container = document.getElementById('history-list');
  const emailItems = analysisHistory.filter(i => i.type !== 'threat');
  if (emailItems.length === 0) {
    container.innerHTML = `<div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48"><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></svg>
      <p>No analyses yet. <a href="#" onclick="navigateTo('analyze');return false;">Analyze an email</a> first.</p>
    </div>`;
    return;
  }
  const items = emailItems.map(item => {
    const isSpam = item.classification === 'Spam';
    const date = new Date(item.timestamp).toLocaleString();
    return `<div class="history-item" onclick="openHistoryDetail('${item.id}')">
      <div class="history-classification">
        <span class="history-verdict ${isSpam ? 'spam' : 'ham'}">${isSpam ? 'SPAM' : 'HAM'}</span>
        <span class="history-conf">${item.confidence}%</span>
      </div>
      <div class="history-info">
        <div class="history-subject">${escHtml(item.subject || '(No Subject)')}</div>
        <div class="history-meta">${escHtml(item.sender || '—')} · ${date}</div>
      </div>
      <span class="history-mode-badge ${item.analysis_mode}">${item.analysis_mode === 'ultra' ? 'ULTRA AI' : 'KAVACHAM AI'}</span>
    </div>`;
  }).join('');
  container.innerHTML = `<div class="history-list">${items}</div>`;
}

function openHistoryDetail(id) {
  const item = analysisHistory.find(i => i.id === id);
  if (!item) return;
  if (item.type === 'threat') {
    // Threat-Discovery entries are shown on the Phishing Checker page table
    showToast('Threat-Discovery results are shown in the Phishing Checker table.', 'info');
    return;
  }
  const modal = document.getElementById('history-modal');
  const modalBody = document.getElementById('modal-body');
  document.getElementById('modal-subject').textContent = item.subject || '(No Subject)';
  const isSpam = item.classification === 'Spam';
  let html = `
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;">
      <span class="signal-badge ${isSpam ? 'spam' : 'ham'}" style="font-size:14px;padding:6px 16px;">${isSpam ? 'SPAM' : 'NOT SPAM'}</span>
      <span style="font-size:13px;color:var(--text-secondary);">Model Confidence: <strong>${item.confidence}%</strong></span>
      <span class="history-mode-badge ${item.analysis_mode}">${item.analysis_mode === 'ultra' ? 'ULTRA AI' : 'KAVACHAM AI'}</span>
    </div>
    <div class="info-list" style="margin-bottom:20px;">
      <div class="info-item"><span class="info-label">Sender</span><span class="info-val">${escHtml(item.sender)}</span></div>
      <div class="info-item"><span class="info-label">Date</span><span class="info-val">${new Date(item.timestamp).toLocaleString()}</span></div>
    </div>
  `;
  if (item.result) {
    const signals = (item.result.influential_signals || (item.result.anveshak && item.result.anveshak.influential_signals) || []);
    if (signals.length > 0) {
      html += `<h4 style="font-size:13px;color:var(--text-muted);margin-bottom:12px;text-transform:uppercase;letter-spacing:.08em;">Influential Signals</h4>`;
      html += `<div id="modal-signals"></div>`;
    }
    if (item.analysis_mode === 'ultra' && item.result.gemini && item.result.gemini.success) {
      html += `<div style="margin-top:16px;"><h4 style="font-size:13px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em;">Kavacham AI Pro Analysis</h4>`;
      html += `<p style="font-size:13px;color:var(--text-secondary);">${escHtml(item.result.gemini.reasoning_summary || '—')}</p>`;
      const agree = item.result.models_agree;
      html += `<div style="margin-top:8px;"><span class="signal-badge ${agree ? 'ham' : 'spam'}">${agree ? 'MODELS AGREE' : 'MODELS DISAGREE'}</span></div></div>`;
    }
  }
  modalBody.innerHTML = html;
  modal.classList.remove('hidden');

  // Render signals if any
  if (item.result) {
    const signals = (item.result.influential_signals || (item.result.anveshak && item.result.anveshak.influential_signals) || []);
    if (signals.length > 0 && document.getElementById('modal-signals')) {
      renderSignalsTable(signals, 'modal-signals');
    }
  }
}

function closeModal() {
  document.getElementById('history-modal').classList.add('hidden');
}

function closePhishModal(e) {
  const overlay = document.getElementById('phish-modal-overlay');
  if (!overlay) return;
  overlay.classList.remove('open');
  setTimeout(() => overlay.classList.add('hidden'), 250);
}

function clearHistory() {
  analysisHistory = [];
  fetch('/api/history', { method: 'DELETE' }).catch(() => {});
  renderHistoryList();
  refreshDashboard();
}

// ---- Dashboard Refresh ----
function refreshDashboard() {
  // Email/ML history only — threat-discovery entries are kept separate
  const emailEntries = analysisHistory.filter(i => i.type !== 'threat');
  const total = emailEntries.length;
  const spam = emailEntries.filter(i => i.classification === 'Spam').length;
  const ham = total - spam;

  animateCount('stat-total', total);
  animateCount('stat-spam', spam);
  animateCount('stat-ham', ham);

  // Live SPA dashboard charts (no-op where canvases do not exist)
  if (window.ANVESHAK_CHARTS) window.ANVESHAK_CHARTS.updateIndexDashboard(emailEntries);

  // Recent analyses (only present on the SPA dashboard page)
  const container = document.getElementById('recent-analyses-list');
  if (!container) return;
  if (total === 0) {
    container.innerHTML = `<div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48"><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></svg>
      <p>No analyses yet. <a href="#" onclick="navigateTo('analyze');return false;">Analyze an email</a> to get started.</p>
    </div>`;
    return;
  }
  const recent = emailEntries.slice(0, 6);
  container.innerHTML = recent.map(item => {
    const isSpam = item.classification === 'Spam';
    return `<div class="history-item" onclick="navigateTo('history')" style="cursor:pointer;">
      <div class="history-classification">
        <span class="history-verdict ${isSpam ? 'spam' : 'ham'}">${isSpam ? 'SPAM' : 'HAM'}</span>
        <span class="history-conf">${item.confidence}%</span>
      </div>
      <div class="history-info">
        <div class="history-subject">${escHtml(item.subject || '(No Subject)')}</div>
        <div class="history-meta">${escHtml(item.sender || '—')} · ${new Date(item.timestamp).toLocaleTimeString()}</div>
      </div>
      <span class="history-mode-badge ${item.analysis_mode}">${item.analysis_mode === 'ultra' ? 'ULTRA AI' : 'KAVACHAM AI'}</span>
    </div>`;
  }).join('');
}

function animateCount(elementId, target) {
  const el = document.getElementById(elementId);
  if (!el || isNaN(target)) return;
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;
  const step = target > current ? 1 : -1;
  const interval = setInterval(() => {
    const val = parseInt(el.textContent) || 0;
    if (val === target) { clearInterval(interval); return; }
    el.textContent = val + step;
  }, 30);
}

// ---- Settings / Gemini Status ----
function initSettings() {
  checkGeminiStatus();
}

async function checkGeminiStatus() {
  const display = document.getElementById('gemini-status-display');
  if (!display) return;
  display.innerHTML = '<div class="loading-spinner-sm"></div><span>Checking Kavacham AI Pro Engine...</span>';
  try {
    const resp = await fetch('/gemini-status');
    const data = await resp.json();
    if (data.reachable) {
      display.innerHTML = `<span class="status-dot green-dot"></span><span class="gemini-connected">Kavacham AI Pro Active — Engine: <code>${data.model}</code></span>`;
    } else if (data.configured) {
      display.innerHTML = `<span class="status-dot red-dot"></span><span class="gemini-error">Engine key configured, status: ${escHtml(data.message)}</span>`;
    } else {
      display.innerHTML = `<span class="status-dot red-dot"></span><span class="gemini-error">Engine key not configured in .env</span>`;
    }
  } catch (e) {
    display.innerHTML = `<span class="status-dot red-dot"></span><span class="gemini-error">Could not reach server</span>`;
  }
}

// ---- Loading ----
function showLoading(text) {
  const overlay = document.getElementById('loading-overlay');
  const textEl = document.getElementById('loading-text');
  textEl.textContent = text || 'Analyzing...';
  overlay.classList.remove('hidden');
}
function hideLoading() {
  document.getElementById('loading-overlay').classList.add('hidden');
}

// ---- Toast ----
function showToast(msg, type) {
  // Remove existing toasts
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const toast = document.createElement('div');
  toast.className = 'toast';
  const colors = { warning: '#f59e0b', error: '#ef4444', success: '#22c55e', info: '#00d4ff' };
  const color = colors[type] || colors.info;
  toast.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:9999;
    background:var(--bg-card);border:1px solid ${color};
    border-radius:8px;padding:14px 20px;
    font-size:13.5px;color:var(--text-primary);
    max-width:380px;box-shadow:0 8px 32px rgba(0,0,0,0.4);
    display:flex;align-items:center;gap:10px;
  `;
  toast.innerHTML = `<span style="color:${color};font-size:16px;">${type === 'error' ? '✕' : type === 'warning' ? '⚠' : '✓'}</span><span>${escHtml(msg)}</span>`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4500);
}

// ---- Utilities ----
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function generateId() {
  return 'h-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7);
}

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
  // Start on dashboard (defensive: some pages have no .page sections)
  navigateTo('dashboard');

  // Load history from server if any, else fall back to localStorage
  fetch('/api/history').then(r => r.json()).then(data => {
    if (data.history && data.history.length > 0) {
      analysisHistory = data.history;
      refreshDashboard();
    } else {
      try {
        const stored = localStorage.getItem('anveshak_history');
        if (stored) {
          const arr = JSON.parse(stored);
          if (Array.isArray(arr) && arr.length) {
            analysisHistory = arr.slice(0, 50);
            refreshDashboard();
            renderLocalHistoryList();
          }
        }
      } catch (e) { /* storage unavailable — ignore */ }
    }
  }).catch(() => {});

  // Manual analyzer wiring (dashboard.html / login.html)
  initManualAnalyzers();

  // Gmail dashboard charts
  if (window.GMAIL_DASH_DATA && window.ANVESHAK_CHARTS) {
    window.ANVESHAK_CHARTS.initGmailDashboard(window.GMAIL_DASH_DATA);
  }

  // Reveal anything already rendered above the fold
  if (window.AnveshakEffects) {
    window.setTimeout(function () {
      window.AnveshakEffects.revealVisible(document);
    }, 160);
  }
});

// ====================================================================
// 4-CATEGORY BENCHMARK TEST SUITE
// ====================================================================
const TEST_SUITE_CASES = [
  // Category 1: Real Genuine Mail
  {
    id: 'c1-1',
    category: 'Category 1',
    categoryName: 'Real Genuine',
    expected: 'Not Spam',
    subject: 'Project Review Meeting',
    sender: 'coordinator@university.edu',
    body: 'Hi Aditya, this is a reminder that the project review meeting is scheduled for Friday at 11:00 AM in Lab 204. Please bring your current project files and be prepared to explain the work completed so far.',
    signalsDescription: 'Normal academic informational reminder'
  },
  {
    id: 'c1-2',
    category: 'Category 1',
    categoryName: 'Real Genuine',
    expected: 'Not Spam',
    subject: 'Assignment Submission Reminder',
    sender: 'dept@university.edu',
    body: 'Dear Students, this is a reminder that the database assignment is due on Monday. Please submit your completed assignment through the university portal before the deadline.',
    signalsDescription: 'Standard departmental reminder without urgency manipulation'
  },
  // Category 2: Obvious Spam
  {
    id: 'c2-1',
    category: 'Category 2',
    categoryName: 'Obvious Spam',
    expected: 'Spam',
    subject: 'Congratulations! You Won 50,00,000!',
    sender: 'prizes@international-lotto.xyz',
    body: 'CONGRATULATIONS! Your email address has been randomly selected as the winner of 50,00,000. To claim your prize, send your full name, phone number, bank account details and OTP immediately. Claim your prize NOW!',
    signalsDescription: 'Financial lure, urgent OTP request, lottery winner claim'
  },
  {
    id: 'c2-2',
    category: 'Category 2',
    categoryName: 'Obvious Spam',
    expected: 'Spam',
    subject: 'URGENT: Your Bank Account Will Be Blocked',
    sender: 'security@secure-verify-auth.xyz',
    body: 'Dear Customer, your bank account will be permanently blocked today due to suspicious activity. Verify your account immediately by providing your login password, debit card number and OTP. Failure will result in permanent suspension.',
    signalsDescription: 'Severe artificial urgency, credential harvesting, OTP solicitation'
  },
  // Category 3: Looks Genuine But Is Actually Spam (Sophisticated Phishing)
  {
    id: 'c3-1',
    category: 'Category 3',
    categoryName: 'Phishing Scam',
    expected: 'Spam',
    subject: 'Action Required: Unclaimed parcel waiting at regional depot',
    sender: 'delivery@express-shipping-notice.com',
    body: 'Dear customer, you have an unclaimed package on hold at our regional facility. Pay the $2.99 processing fee immediately to schedule dispatch before it is returned to sender.',
    signalsDescription: 'Delivery lure with urgent fee demand'
  },
  {
    id: 'c3-2',
    category: 'Category 3',
    categoryName: 'Phishing Scam',
    expected: 'Spam',
    subject: 'Microsoft 365 Account Suspension Warning',
    sender: 'admin@office-system-portal.com',
    body: 'Unusual login activity detected. Your corporate account will be permanently suspended within 24 hours. Verify your login credentials and password immediately to restore access.',
    signalsDescription: 'IT impersonation with urgency and credential harvesting'
  },
  // Category 4: Looks Suspicious But Is Actually Genuine (Adversarial False-Positive Stress Tests)
  {
    id: 'c4-1',
    category: 'Category 4',
    categoryName: 'Adversarial Ham',
    expected: 'Not Spam',
    subject: 'URGENT SECURITY ALERT – New Login Detected',
    sender: 'it-security@university.edu',
    body: 'Hi Aditya, this is a legitimate security notification from the university IT department. A new login was detected from a new device. If this was you, no action is required. We will NEVER ask you to provide your password, OTP or recovery code by email.',
    signalsDescription: 'Contains "URGENT", "ALERT", "SECURITY", but explicit negation of password request'
  },
  {
    id: 'c4-2',
    category: 'Category 4',
    categoryName: 'Adversarial Ham',
    expected: 'Not Spam',
    subject: 'PAYMENT CONFIRMATION – Registration Successfully Completed',
    sender: 'accounts@university.edu',
    body: 'Dear Aditya, your registration payment of 500 has been successfully received. This email is only a payment confirmation for your records. No further payment is required. Please do not share your password or OTP with anyone.',
    signalsDescription: 'Contains "PAYMENT", "CONFIRMATION", but is a receipt with negation "No payment is required"'
  },
  {
    id: 'c4-3',
    category: 'Category 4',
    categoryName: 'Adversarial Ham',
    expected: 'Not Spam',
    subject: 'Congratulations – Your Project Has Been Selected',
    sender: 'events@university.edu',
    body: 'Dear Aditya, congratulations! Your project has been selected for the final presentation round of the university technology competition. There is no registration fee, payment requirement or purchase associated with this selection.',
    signalsDescription: 'Contains "CONGRATULATIONS", "SELECTED", but clearly states "no payment required"'
  },
  {
    id: 'c4-4',
    category: 'Category 4',
    categoryName: 'Adversarial Ham',
    expected: 'Not Spam',
    subject: 'LIMITED SEATS – Cybersecurity Workshop Registration',
    sender: 'workshops@university.edu',
    body: 'Dear Students, registration is now open for the upcoming cybersecurity awareness workshop. Seats are limited to 50 participants. Registration is completely free. This is an official academic workshop organized by the department.',
    signalsDescription: 'Contains "LIMITED", "CYBERSECURITY", "REGISTRATION", but is purely academic'
  }
];

let testSuiteResults = {};

function initTestSuite() {
  renderTestSuiteRows();
}

function renderTestSuiteRows() {
  const tbody = document.getElementById('testsuite-rows');
  if (!tbody) return;

  tbody.innerHTML = TEST_SUITE_CASES.map(tc => {
    const res = testSuiteResults[tc.id];
    let resultCol = '<span style="color:var(--text-muted);font-size:12px;">Not executed</span>';
    let statusCol = '<span class="signal-badge neutral" style="font-size:11px;">PENDING</span>';

    if (res) {
      const isSpam = res.prediction === 'Spam';
      const passed = (res.prediction === tc.expected);
      resultCol = `<span class="signal-badge ${isSpam ? 'spam' : 'ham'}">${res.prediction} (${res.confidence}%)</span>`;
      statusCol = passed
        ? `<span class="signal-badge ham" style="font-weight:700;">✓ PASSED</span>`
        : `<span class="signal-badge spam" style="font-weight:700;">✗ FAILED</span>`;
    }

    const expBadge = tc.expected === 'Spam'
      ? `<span class="signal-badge spam">SPAM</span>`
      : `<span class="signal-badge ham">NOT SPAM</span>`;

    return `
      <tr>
        <td>
          <span style="font-size:11px;font-weight:700;color:var(--accent);display:block;">${tc.category}</span>
          <span style="font-size:10px;color:var(--text-muted);">${tc.categoryName}</span>
        </td>
        <td>
          <div style="font-weight:600;font-size:13px;color:var(--text-primary);margin-bottom:2px;">${escHtml(tc.subject)}</div>
          <div style="font-size:11px;color:var(--text-muted);">${escHtml(tc.signalsDescription)}</div>
        </td>
        <td>${expBadge}</td>
        <td>${resultCol}</td>
        <td>${statusCol}</td>
        <td style="text-align:right;">
          <button class="btn btn-ghost btn-sm" onclick="runSingleTestCase('${tc.id}')" style="padding:4px 8px;font-size:11px;">
            Run
          </button>
          <button class="btn btn-secondary btn-sm" onclick="loadTestCaseToAnalyzer('${tc.id}')" style="padding:4px 8px;font-size:11px;margin-left:4px;">
            Load
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

async function runSingleTestCase(id) {
  const tc = TEST_SUITE_CASES.find(t => t.id === id);
  if (!tc) return;

  showLoading(`Evaluating test case: ${tc.subject}...`);
  try {
    const resp = await fetch('/analyze-email-simple', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        subject: tc.subject,
        sender: tc.sender,
        body: tc.body
      })
    });
    const data = await resp.json();
    hideLoading();

    if (data.success) {
      testSuiteResults[id] = data;
      renderTestSuiteRows();
      updateTestSuiteSummary();
      showToast(`Evaluated: ${data.prediction} (${data.confidence}%)`, data.prediction === tc.expected ? 'success' : 'error');
    } else {
      showToast('Evaluation failed: ' + (data.error || 'Server error'), 'error');
    }
  } catch (err) {
    hideLoading();
    showToast('Network error: ' + err.message, 'error');
  }
}

async function runAllTestSuite() {
  const btn = document.getElementById('btn-run-all-tests');
  if (btn) btn.disabled = true;

  showLoading('Running complete 10-case adversarial benchmark...');
  let passedCount = 0;

  for (const tc of TEST_SUITE_CASES) {
    try {
      const resp = await fetch('/analyze-email-simple', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: tc.subject,
          sender: tc.sender,
          body: tc.body
        })
      });
      const data = await resp.json();
      if (data.success) {
        testSuiteResults[tc.id] = data;
        if (data.prediction === tc.expected) passedCount++;
      }
    } catch (e) {
      console.error(e);
    }
  }

  hideLoading();
  if (btn) btn.disabled = false;
  renderTestSuiteRows();
  updateTestSuiteSummary();
  showToast(`Benchmark complete: ${passedCount} / ${TEST_SUITE_CASES.length} passed`, passedCount === TEST_SUITE_CASES.length ? 'success' : 'warning');
}

function updateTestSuiteSummary() {
  const total = TEST_SUITE_CASES.length;
  let evaluated = 0;
  let passed = 0;
  let falsePositives = 0;

  TEST_SUITE_CASES.forEach(tc => {
    const res = testSuiteResults[tc.id];
    if (res) {
      evaluated++;
      if (res.prediction === tc.expected) {
        passed++;
      } else if (tc.expected === 'Not Spam' && res.prediction === 'Spam') {
        falsePositives++;
      }
    }
  });

  const card = document.getElementById('testsuite-summary-card');
  if (card && evaluated > 0) {
    card.style.display = 'block';
    const badge = document.getElementById('testsuite-score-badge');
    const pct = Math.round((passed / evaluated) * 100);
    badge.textContent = `${pct}% Passed`;
    badge.className = 'verdict-value ' + (pct === 100 ? 'ham' : pct >= 80 ? 'neutral' : 'spam');

    document.getElementById('testsuite-counts').textContent = `${passed} / ${evaluated} Correct (${falsePositives} False Positives)`;
    document.getElementById('testsuite-score-text').textContent =
      falsePositives === 0
        ? 'Zero False Positives: Model successfully distinguishes context-rich alerts and receipts from genuine phishing.'
        : `Identified ${falsePositives} false positives in adversarial cases.`;
  }
}

function loadTestCaseToAnalyzer(id) {
  const tc = TEST_SUITE_CASES.find(t => t.id === id);
  if (!tc) return;

  navigateTo('analyze');
  document.getElementById('input-subject').value = tc.subject;
  document.getElementById('input-sender').value = tc.sender;
  document.getElementById('input-body').value = tc.body;
  showToast(`Loaded test case: "${tc.subject}". Click 'Analyze Email' or choose Ultra AI!`, 'info');
}

/* ====================================================================
   MANUAL ANALYZER (shared across login.html, index.html, dashboard.html)
   ==================================================================== */

function initManualAnalyzers() {
  const textarea = document.getElementById('message-input');
  if (!textarea) return;

  const charCounter = document.getElementById('char-counter');
  const checkBtn = document.getElementById('check-btn');
  const liveStream = document.getElementById('live-stream-output');
  const sampleBtns = document.querySelectorAll('.sample-msg-btn');
  const resultSection = document.getElementById('result-section');

  // Char counter
  function updateCounter() {
    const len = textarea.value.length;
    if (charCounter) charCounter.textContent = len + ' chars';
    if (checkBtn) checkBtn.disabled = len === 0;
  }
  textarea.addEventListener('input', updateCounter);
  updateCounter();

  // Sample buttons
  sampleBtns.forEach(btn => {
    btn.addEventListener('click', function () {
      textarea.value = btn.dataset.sample || '';
      updateCounter();
      textarea.focus();
      if (window.SoundFX) window.SoundFX.click();
      // Trigger live stream immediately
      if (typeof runLiveTokenStream === 'function') runLiveTokenStream(textarea.value);
    });
  });

  // Live token stream (Feature 3)
  let streamTimer = null;
  window.runLiveTokenStream = function runLiveTokenStream(text) {
    if (!liveStream) return;
    if (streamTimer) clearTimeout(streamTimer);
    const tokens = text.toLowerCase().match(/[a-z0-9_]+/g) || [];
    const spammy = ['win', 'prize', 'click', 'claim', 'urgent', 'verify', 'password', 'otp', 'bank', 'lottery', 'congratulations', 'free', 'limited', 'offer', 'expire', 'suspend', 'blocked', 'security', 'alert'];
    const safe = ['meeting', 'scheduled', 'thank', 'please', 'regards', 'team', 'project', 'university', 'department', 'confirmation', 'receipt', 'payment', 'received', 'welcome', 'registration'];
    liveStream.innerHTML = '';
    if (tokens.length === 0) {
      liveStream.innerHTML = '<span class="text-[11px] text-slate-600 italic">Start typing to see real-time token classification...</span>';
      return;
    }
    const sample = tokens.slice(0, 18);
    sample.forEach((tok, i) => {
      const chip = document.createElement('span');
      chip.className = 'token-chip';
      chip.textContent = tok;
      const isSpammy = spammy.some(s => tok.includes(s));
      const isSafe = safe.some(s => tok.includes(s));
      if (isSpammy) chip.classList.add('spam');
      else if (isSafe) chip.classList.add('safe');
      else chip.classList.add('warn');
      chip.style.animationDelay = (i * 35) + 'ms';
      liveStream.appendChild(chip);
    });
  };
  textarea.addEventListener('input', function () {
    if (streamTimer) clearTimeout(streamTimer);
    streamTimer = setTimeout(() => runLiveTokenStream(textarea.value), 220);
  });

  // Main analyze button handler
  if (checkBtn) {
    checkBtn.addEventListener('click', async function () {
      const text = textarea.value.trim();
      if (!text) return;
      if (window.SoundFX) window.SoundFX.click();
      if (resultSection) resultSection.classList.add('hidden');

      showLoading('Computing posterior probabilities with Naive Bayes...');
      try {
        const resp = await fetch('/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text })
        });
        const data = await resp.json();
        hideLoading();
        if (!data.success) {
          showToast('Analysis failed: ' + (data.error || 'Unknown error'), 'error');
          return;
        }
        renderManualResult(data, text);
      } catch (e) {
        hideLoading();
        showToast('Network error: ' + e.message, 'error');
      }
    });
  }
}

function renderManualResult(data, originalText) {
  const resultSection = document.getElementById('result-section');
  const resultCard = document.getElementById('result-card');
  const resultIcon = document.getElementById('result-icon');
  const resultStatus = document.getElementById('result-status');
  const resultExplanation = document.getElementById('result-explanation');
  const resultConfidence = document.getElementById('result-confidence');
  const confidenceBar = document.getElementById('confidence-bar');
  const signalsContainer = document.getElementById('influential-signals-container');
  const signalsList = document.getElementById('influential-signals-list');
  const tokenExplosion = document.getElementById('token-explosion-zone');

  if (!resultSection || !resultCard) return;

  const isSpam = data.prediction === 'Spam';
  playResultSound(isSpam);

  // Icon
  resultIcon.innerHTML = isSpam
    ? '<svg class="w-10 h-10 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>'
    : '<svg class="w-10 h-10 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';

  resultStatus.textContent = isSpam ? 'SPAM DETECTED' : 'NOT SPAM';
  resultStatus.className = 'text-xl font-bold ' + (isSpam ? 'text-red-400' : 'text-emerald-400');

  const conf = data.confidence;
  resultExplanation.textContent = isSpam
    ? 'This message exceeds the Spam decision threshold with patterns commonly found in phishing or promotional schemes.'
    : 'This message satisfies legitimate communication characteristics and falls below the threat decision threshold.';

  resultConfidence.textContent = conf + '%';
  resultConfidence.className = 'text-3xl font-black mono ' + (isSpam ? 'text-red-400' : 'text-emerald-400');

  // Animate confidence bar
  confidenceBar.className = 'h-2.5 rounded-full progress-bar-fill ' + (isSpam ? 'is-spam' : 'is-ham');
  confidenceBar.style.width = '0%';
  void confidenceBar.offsetWidth;
  confidenceBar.style.width = Math.min(conf, 100) + '%';

  // Influential signals table
  if (signalsContainer && signalsList && data.influential_signals && data.influential_signals.length) {
    signalsContainer.classList.remove('hidden');
    signalsList.innerHTML = data.influential_signals.map(s => {
      const cls = s.status === 'Spam signal' ? 'spam' : s.status === 'Ham / Safe signal' ? 'ham' : 'neutral';
      const label = s.status === 'Spam signal' ? 'Spam Signal' : s.status === 'Ham / Safe signal' ? 'Safe Signal' : 'Context-Dependent';
      return `<div class="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/50 border border-slate-800/60">
        <span class="signal-token mono text-xs">${escHtml(s.token)}</span>
        <span class="signal-badge ${cls} text-[10px]">${label}</span>
        <span class="signal-score mono text-xs">${s.score > 0 ? '+' : ''}${s.score}</span>
      </div>`;
    }).join('');
  } else if (signalsContainer) {
    signalsContainer.classList.add('hidden');
  }

  // Token explosion (Feature 2)
  if (tokenExplosion) {
    tokenExplosion.innerHTML = '';
    if (data.influential_signals && data.influential_signals.length) {
      data.influential_signals.forEach((s, i) => {
        const chip = document.createElement('span');
        chip.className = 'token-chip burst-token';
        chip.textContent = s.token;
        const cls = s.status === 'Spam signal' ? 'spam' : s.status === 'Ham / Safe signal' ? 'ham' : 'warn';
        chip.classList.add(cls);
        chip.style.setProperty('--tx', ((Math.random() - 0.5) * 240) + 'px');
        chip.style.setProperty('--ty', ((Math.random() - 0.5) * 160) + 'px');
        chip.style.animationDelay = (i * 60) + 'ms';
        tokenExplosion.appendChild(chip);
      });
    }
  }

  // Persist to localStorage history
  try {
    const stored = localStorage.getItem('anveshak_history');
    const arr = stored ? JSON.parse(stored) : [];
    arr.unshift({
      id: 'local-' + Date.now(),
      sender: '—',
      subject: '(Manual Analysis)',
      classification: data.prediction,
      confidence: data.confidence,
      analysis_mode: 'anveshak',
      timestamp: new Date().toISOString(),
      result: data
    });
    localStorage.setItem('anveshak_history', JSON.stringify(arr.slice(0, 50)));
  } catch (e) {}

  resultSection.classList.remove('hidden');
  resultCard.classList.remove('hidden');
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderLocalHistoryList() {
  const container = document.getElementById('recent-analyses-list');
  if (!container) return;
  try {
    const stored = localStorage.getItem('anveshak_history');
    if (stored) {
      const arr = JSON.parse(stored);
      if (arr.length) {
        container.innerHTML = arr.slice(0, 6).map(item => {
          const isSpam = item.classification === 'Spam';
          return `<div class="history-item" onclick="navigateTo('history')" style="cursor:pointer;">
            <div class="history-classification">
              <span class="history-verdict ${isSpam ? 'spam' : 'ham'}">${isSpam ? 'SPAM' : 'HAM'}</span>
              <span class="history-conf">${item.confidence}%</span>
            </div>
            <div class="history-info">
              <div class="history-subject">${escHtml(item.subject || '(No Subject)')}</div>
              <div class="history-meta">${escHtml(item.sender || '—')} · ${new Date(item.timestamp).toLocaleTimeString()}</div>
            </div>
            <span class="history-mode-badge ${item.analysis_mode}">${item.analysis_mode === 'ultra' ? 'ULTRA AI' : 'KAVACHAM AI'}</span>
          </div>`;
        }).join('');
        return;
      }
    }
  } catch (e) {}
  container.innerHTML = `<div class="empty-state">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48"><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></svg>
    <p>No analyses yet. <a href="#" onclick="navigateTo('analyze');return false;">Analyze an email</a> to get started.</p>
  </div>`;
}

// ====================================================================
// THREAT DISCOVERY — PHISHING CHECKER
// ====================================================================
let lastThreatRequest = null; // { type: 'url'|'file'|'message', payload (FormData|object), target }
let lastThreatResult = null;

function initThreatChecker() {
  // Re-render table each time the page opens
  loadThreatHistory();
  renderThreatHistoryTable();
  checkThreatStatus();

  // File drop-zone wiring (attach only once)
  const fileInput = document.getElementById('threat-file-input');
  const dropZone = document.getElementById('threat-file-drop');
  if (fileInput && !fileInput.dataset.wired) {
    fileInput.dataset.wired = '1';
    dropZone.addEventListener('click', function () { fileInput.click(); });
    fileInput.addEventListener('change', function () {
      const f = fileInput.files && fileInput.files[0];
      const label = document.getElementById('threat-file-label');
      const meta = document.getElementById('threat-file-meta');
      if (f) {
        label.textContent = f.name;
        meta.textContent = (f.type || 'Unknown type') + ' · ' + formatBytes(f.size);
        dropZone.classList.add('has-file');
      } else {
        label.textContent = 'Click to choose a file';
        meta.textContent = '';
        dropZone.classList.remove('has-file');
      }
    });
  }
}

/* ====================================================================
   GMAIL PAGE — polished connection states
   ==================================================================== */

function initGmailPage() {
  // If the user navigated away mid-connect, restore the button to its
  // default state rather than leaving a hanging "Connecting..." spinner.
  const btn = document.getElementById('gmail-connect-btn');
  if (btn && btn.dataset.busy) {
    delete btn.dataset.busy;
    btn.classList.remove('connecting');
    btn.disabled = false;
    const label = document.getElementById('gmail-connect-label');
    const spinner = document.getElementById('gmail-connect-spinner');
    if (label) label.textContent = 'Connect with Gmail';
    if (spinner) spinner.classList.add('hidden');
  }
}

function connectGmail(btn) {
  if (!btn || btn.dataset.busy) return;
  btn.dataset.busy = '1';
  btn.classList.add('connecting');
  btn.disabled = true;
  const label = document.getElementById('gmail-connect-label');
  const spinner = document.getElementById('gmail-connect-spinner');
  if (label) label.textContent = 'Connecting to Google...';
  if (spinner) spinner.classList.remove('hidden');
  if (window.SoundFX) window.SoundFX.click();
  // Brief pause so the connecting state is visible before the OAuth redirect
  window.setTimeout(function () {
    window.location.href = '/authorize';
  }, 700);
}

function disconnectGmail() {
  const ok = window.confirm('Disconnect your Gmail account from Kavacham AI? You can reconnect anytime.');
  if (!ok) return;
  window.location.href = '/logout';
}

/* ====================================================================
   PHISHING CHECKER — Email Phishing Analyzer (local ML primary)
   ==================================================================== */

function initPhishingChecker() {
  // Reset any in-flight analyzer state from a previous abandoned run.
  const btn = document.getElementById('phish-analyze-btn');
  if (btn) btn.disabled = false;
}

function clearPhishingCheck() {
  ['phish-sender', 'phish-subject', 'phish-body', 'phish-urls'].forEach(function (id) {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const stages = document.getElementById('phishing-stages');
  const result = document.getElementById('phishing-result');
  if (stages) stages.classList.add('hidden');
  if (result) result.classList.add('hidden');
  const btn = document.getElementById('phish-analyze-btn');
  if (btn) btn.disabled = false;
  if (window.SoundFX) window.SoundFX.click();
}

var PHISH_TYPE_SKIP = ['no_indicators', 'risk_escalation', 'ml_unavailable', 'spam_classification', 'influential_tokens'];
var PHISH_ICONS = {
  url: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><circle cx="12" cy="12" r="9"/><path d="M3.5 12h17M12 3.5c2.5 2.6 3.9 5.4 3.9 8.5s-1.4 5.9-3.9 8.5M12 3.5C9.5 6.1 8.1 8.9 8.1 12s1.4 5.9 3.9 8.5"/></svg>',
  user: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><circle cx="12" cy="12" r="9"/><path d="M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>'
};

function mapIndicatorGroup(type) {
  var t = String(type || '').toLowerCase();
  var groups = [
    { keys: ['suspicious_url', 'anchor_mismatch', 'ip_url', 'idn_homograph', 'encoded_url', 'shortened_url', 'suspicious_tld', 'abused_tld', 'url', 'qr_phishing'], label: 'Suspicious URL', icon: PHISH_ICONS.url, scope: 'warn' },
    { keys: ['reply_to_mismatch', 'claimed_role_sender_mismatch', 'brand_impersonation', 'brand_free_mail_mismatch', 'service_localpart_free_mail'], label: 'Sender mismatch', icon: PHISH_ICONS.user, scope: 'warn' },
    { keys: ['return_path_mismatch'], label: 'Authentication issue', icon: PHISH_ICONS.lock, scope: 'warn' },
    { keys: ['lookalike_domain'], label: 'Domain anomaly', icon: PHISH_ICONS.globe, scope: 'warn' },
    { keys: ['credential_harvesting', 'login_request', 'password_reset', 'otp_request', 'otp_password_request', 'kyc_request', 'kyc_scam'], label: 'Credential request', icon: PHISH_ICONS.lock, scope: 'warn' },
    { keys: ['risky_attachment', 'vt_hash_flag'], label: 'Suspicious attachment', icon: PHISH_ICONS.file, scope: 'warn' },
    { keys: ['urgent_verification', 'unusual_urgency', 'account_suspension', 'urgent_payment', 'coercive_combo', 'reward_bait', 'lottery_prize', 'digital_arrest', 'fake_support', 'fake_delivery', 'refund_scam', 'payment_scam', 'job_scam', 'phishing'], label: 'Urgency / Social engineering', icon: PHISH_ICONS.alert, scope: 'warn' },
    { keys: ['executive_impersonation', 'finance_impersonation', 'hr_impersonation', 'bank_impersonation', 'vendor_impersonation', 'invoice_manipulation', 'confidential_request', 'gift_card_request', 'bank_account_change'], label: 'Impersonation / BEC', icon: PHISH_ICONS.shield, scope: 'warn' }
  ];
  for (var i = 0; i < groups.length; i++) {
    if (groups[i].keys.indexOf(t) !== -1) return groups[i];
  }
  return { keys: [], label: 'Security signal', icon: PHISH_ICONS.shield, scope: 'warn' };
}

function sevColor(sev) {
  sev = String(sev || '').toLowerCase();
  if (sev === 'high' || sev === 'critical') return '#f87171';
  if (sev === 'medium' || sev === 'moderate') return '#fbbf24';
  if (sev === 'low') return '#8b9ab8';
  return '#8b9ab8';
}

async function runPhishingCheck() {
  const subjectEl = document.getElementById('phish-subject');
  const bodyEl = document.getElementById('phish-body');
  const subject = (subjectEl.value || '').trim();
  const body = (bodyEl.value || '').trim();
  if (!subject && !body) {
    showToast('Please enter at least an email subject or message content.', 'warning');
    bodyEl.focus();
    return;
  }

  const sender = (document.getElementById('phish-sender').value || '').trim();
  const urls = (document.getElementById('phish-urls').value || '').trim();
  const ultraEl = document.getElementById('phish-ultra');
  const ultra = !!(ultraEl && ultraEl.checked);

  const analyzeBtn = document.getElementById('phish-analyze-btn');
  analyzeBtn.disabled = true;
  if (window.SoundFX) window.SoundFX.scan();

  // Build the stage checklist from what the backend will actually process:
  // stages are never invented — only requested signals appear.
  const stages = [{ k: 'content', label: 'Content analyzed' }];
  if (sender) stages.push({ k: 'sender', label: 'Sender checked' });
  const bodyHasUrl = /(https?:\/\/|www\.)/i.test(body);
  if (bodyHasUrl || urls) stages.push({ k: 'urls', label: 'URLs being inspected' });
  stages.push({ k: 'signals', label: 'Security signals' });
  stages.push({ k: 'assess', label: 'Final assessment' });

  const stagesWrap = document.getElementById('phishing-stages');
  const resultWrap = document.getElementById('phishing-result');
  const stageList = document.getElementById('phish-stage-list');
  stageList.innerHTML = stages.map(s =>
    `<li class="phish-stage-item" id="phish-stage-${s.k}">
       <span class="stage-ic"><span class="phish-stage-spin"></span></span>
       <span>${escHtml(s.label)}</span>
     </li>`).join('');
  stagesWrap.classList.remove('hidden');
  resultWrap.classList.add('hidden');

  const checkSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14"><polyline points="20 6 9 17 4 12"/></svg>';
  const markDone = function (k) {
    const el = document.getElementById('phish-stage-' + k);
    if (!el) return;
    el.classList.remove('active');
    el.classList.add('done');
    const ic = el.querySelector('.stage-ic');
    if (ic) ic.innerHTML = checkSvg;
  };

  // Sequential reveal — each tick completes the previous stage only if the
  // request is still running (timing staggers the display; the stages list
  // itself always matches the real backend processing for these inputs).
  let idx = 0;
  const runTick = function () {
    if (idx > 0) markDone(stages[idx - 1].k);
    if (idx < stages.length) {
      const el = document.getElementById('phish-stage-' + stages[idx].k);
      if (el) el.classList.add('active');
    }
    idx += 1;
  };
  const interval = window.setInterval(runTick, 420);
  const finishStages = function () {
    window.clearInterval(interval);
    stages.forEach(s => markDone(s.k));
  };

  try {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 45000);
    const resp = await fetch('/api/phishing-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({ sender: sender, subject: subject, body: body, urls: urls, ultra_ai: ultra })
    });
    window.clearTimeout(timeout);
    finishStages();
    analyzeBtn.disabled = false;

    const data = await resp.json();
    if (!data || data.success === false) {
      showToast(data && data.error ? data.error : 'Analysis failed. Please try again.', 'error');
      stagesWrap.classList.add('hidden');
      return;
    }

    renderPhishingResult(data);
    resultWrap.classList.remove('hidden');
    resultWrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    finishStages();
    analyzeBtn.disabled = false;
    stagesWrap.classList.add('hidden');
    showToast('Analysis request timed out or failed. Please try again.', 'error');
  }
}

function renderPhishingResult(data) {
  const cls = data.classification || {};
  const label = cls.label === 'SPAM' ? 'SPAM' : (cls.label === 'HAM' ? 'NOT SPAM' : 'UNAVAILABLE');
  const isSpam = label === 'SPAM';

  // Classification icon + value
  const iconEl = document.getElementById('phish-class-icon');
  iconEl.className = 'phish-big-icon ' + (isSpam ? 'spam' : 'ham');
  iconEl.innerHTML = isSpam
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="34" height="34"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="34" height="34"><circle cx="12" cy="12" r="9"/><polyline points="8.5 12.5 11 15 15.5 9.5"/></svg>';
  const classEl = document.getElementById('phish-classification');
  classEl.textContent = label;
  classEl.className = 'phish-class-value mono ' + (isSpam ? 'spam' : 'ham');

  // Confidence — only show a value the model actually produced
  const confEl = document.getElementById('phish-confidence');
  const conf = cls.confidence;
  if (typeof conf === 'number' && isFinite(conf) && conf > 0) {
    confEl.textContent = 'Confidence: ' + conf + '%';
  } else {
    confEl.textContent = 'Confidence not available';
  }
  const probEl = document.getElementById('phish-prob');
  if (typeof cls.probability_spam === 'number' && isFinite(cls.probability_spam)) {
    const thr = cls.decision_threshold != null ? cls.decision_threshold : '—';
    probEl.textContent = 'Spam probability: ' + cls.probability_spam + '% · Threshold: ' + thr + '%';
  } else {
    probEl.textContent = '';
  }

  // Risk ring + phishing assessment
  const security = data.security || {};
  const score = Math.min(100, Math.max(0, security.risk_score != null ? security.risk_score : 0));
  let verdict = String(security.verdict || 'SUSPICIOUS').replace(/_/g, ' ');
  const lvlKey = verdict === 'HIGH RISK' ? 'HIGH RISK' : verdict;
  document.getElementById('phish-risk-num').textContent = score;
  const ring = document.getElementById('phish-risk-ring');
  ring.className = 'threat-score-ring ' + levelClass(lvlKey);
  ring.style.setProperty('--score', score + '%');
  const verdictEl = document.getElementById('phish-verdict');
  verdictEl.textContent = verdict;
  verdictEl.className = 'threat-risk-value ' + levelClass(lvlKey);

  // Kavacham AI Pro note — only shown when Pro is genuinely unavailable
  const proNote = document.getElementById('phish-pro-note');
  if (data.ai_explanation) proNote.classList.add('hidden');
  else proNote.classList.remove('hidden');

  // Threat indicator cards (only actually detected signals)
  const rawEvidence = (data.evidence && data.evidence.length) ? data.evidence : (data.threats || []);
  const threats = rawEvidence.filter(function (t) {
    if (PHISH_TYPE_SKIP.indexOf(t.type) !== -1) return false;
    const sev = String(t.severity || 'low').toLowerCase();
    return sev === 'medium' || sev === 'high' || sev === 'critical';
  });
  const indicatorsEl = document.getElementById('phish-indicators');
  if (threats.length) {
    const grouped = {};
    threats.forEach(function (t) {
      if (PHISH_TYPE_SKIP.indexOf(t.type) !== -1) return;
      const g = mapIndicatorGroup(t.type);
      if (!grouped[g.label]) {
        grouped[g.label] = { label: g.label, icon: g.icon, scope: g.scope, ev: [], sev: 'low' };
      }
      const ev = (t.evidence || '').trim();
      if (ev && grouped[g.label].ev.indexOf(ev) === -1) grouped[g.label].ev.push(ev);
      const sev = String(t.severity || 'low').toLowerCase();
      if (sev === 'high' || sev === 'critical') grouped[g.label].sev = 'high';
      else if (sev === 'medium' && grouped[g.label].sev !== 'high') grouped[g.label].sev = 'medium';
    });
    const cards = Object.keys(grouped).map(k => grouped[k]);
    indicatorsEl.innerHTML = cards.length
      ? cards.map(c => `
        <div class="phish-indicator-card ${c.scope}">
          <span class="ind-ic">${c.icon}</span>
          <div class="ind-body">
            <div class="ind-title">${escHtml(c.label)}</div>
            <div class="ind-ev">${escHtml(c.ev.slice(0, 2).join(' · '))}${c.ev.length > 2 ? ' · +' + (c.ev.length - 2) + ' more' : ''}</div>
            <div class="ind-sev" style="color:${sevColor(c.sev)}">${escHtml(c.sev)} severity</div>
          </div>
        </div>`).join('')
      : emptyIndicatorCard();
  } else {
    indicatorsEl.innerHTML = emptyIndicatorCard();
  }

  // Explanation — "Why Kavacham AI flagged this"
  const reasonsEl = document.getElementById('phish-reasons');
  const reasons = (data.top_reasons && data.top_reasons.length) ? data.top_reasons : [];
  reasonsEl.innerHTML = reasons.length
    ? reasons.map(r => `<li style="--bullet:${sevColor(r.severity || r.reason && 'low')};">${escHtml(r.reason || r)}</li>`).join('')
    : `<li>No strong threat signals were detected by the local engines.</li>`;

  const explainEl = document.getElementById('phish-explain');
  const contextEl = document.getElementById('phish-context-note');
  const ai = data.ai_explanation;
  const spamSummary = data.spam_analysis && data.spam_analysis.summary;
  if (ai && (ai.explanation || ai.reasoning_summary)) {
    explainEl.textContent = ai.explanation || ai.reasoning_summary || '';
    contextEl.textContent = 'Explanation provided by Kavacham AI Pro; the primary classification remains the local Kavacham AI model.';
  } else if (spamSummary) {
    explainEl.textContent = 'Local Kavacham AI analysis: ' + spamSummary;
    contextEl.textContent = 'Kavacham AI Pro was unavailable, so this explanation comes from the local engine only.';
  } else {
    explainEl.textContent = 'The result reflects the local Kavacham AI model and deterministic security indicators.';
    contextEl.textContent = '';
  }

  // High-risk alert modal for SPAM / HIGH RISK
  const isHighRisk = (verdict === 'HIGH RISK' || (score >= 70 && isSpam));
  if (isHighRisk) {
    const msgEl = document.getElementById('phish-modal-msg');
    if (msgEl) msgEl.textContent = 'This message contains strong indicators of phishing or credential theft. Do not click any links, do not provide credentials, and report to your IT security team.';
    const overlay = document.getElementById('phish-modal-overlay');
    if (overlay) {
      overlay.classList.remove('hidden');
      requestAnimationFrame(() => overlay.classList.add('open'));
    }
  }
}

function emptyIndicatorCard() {
  return `<div class="phish-indicator-card info" style="grid-column:1/-1;">
    <span class="ind-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="20 6 9 17 4 12"/></svg></span>
    <div class="ind-body">
      <div class="ind-title">No threat indicators detected</div>
      <div class="ind-ev">No suspicious URLs, sender mismatches, credential requests or social-engineering signals were found in this message.</div>
    </div>
  </div>`;
}

function formatBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

async function checkThreatStatus() {
  const dot = document.getElementById('threat-api-dot');
  const text = document.getElementById('threat-api-text');
  if (!dot || !text) return;
  try {
    const resp = await fetch('/api/threat/status');
    const data = await resp.json();
    if (data.configured && data.reachable) {
      dot.className = 'threat-status-dot ok';
      text.textContent = 'Kavacham AI Pro threat engine active — real-time analysis available';
    } else if (data.configured) {
      dot.className = 'threat-status-dot warn';
      text.textContent = 'Threat engine configured but busy (' + (data.message || 'degraded') + ') — results may be unavailable';
    } else {
      dot.className = 'threat-status-dot off';
      text.textContent = 'Kavacham AI Pro unavailable. Kavacham AI local analysis remains active.';
    }
  } catch (e) {
    dot.className = 'threat-status-dot off';
    text.textContent = 'Could not reach threat engine status';
  }
}

function analyzeThreatUrl() {
  const input = document.getElementById('threat-url-input');
  const url = (input && input.value || '').trim();
  if (!url) {
    showToast('Please paste a URL to analyze.', 'warning');
    input && input.focus();
    return;
  }
  if (window.SoundFX) window.SoundFX.click();
  lastThreatRequest = { type: 'url', payload: { url: url }, target: url };
  runThreatAnalysis('/api/threat/url',
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url }) },
    url);
}

function analyzeThreatFile() {
  const input = document.getElementById('threat-file-input');
  const file = input && input.files && input.files[0];
  if (!file) {
    showToast('Please choose a file to analyze.', 'warning');
    return;
  }
  if (window.SoundFX) window.SoundFX.click();
  const fd = new FormData();
  fd.append('file', file);
  lastThreatRequest = { type: 'file', payload: fd, target: file.name };
  runThreatAnalysis('/api/threat/file', { method: 'POST', body: fd }, file.name);
}

function analyzeThreatMessage() {
  const input = document.getElementById('threat-message-input');
  const msg = (input && input.value || '').trim();
  if (!msg) {
    showToast('Please paste a message to analyze.', 'warning');
    input && input.focus();
    return;
  }
  if (window.SoundFX) window.SoundFX.click();
  lastThreatRequest = { type: 'message', payload: { message: msg }, target: msg.slice(0, 60) };
  runThreatAnalysis('/api/threat/message',
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: msg }) },
    msg.slice(0, 60));
}

function retryLastThreatAnalysis() {
  if (!lastThreatRequest) {
    showToast('Nothing to analyze yet.', 'info');
    return;
  }
  if (lastThreatRequest.type === 'url') {
    analyzeThreatUrl();
  } else if (lastThreatRequest.type === 'message') {
    analyzeThreatMessage();
  } else if (lastThreatRequest.type === 'file') {
    // File payload already stored in FormData at first run
    if (window.SoundFX) window.SoundFX.click();
    runThreatAnalysis('/api/threat/file', { method: 'POST', body: lastThreatRequest.payload }, lastThreatRequest.target);
  }
}

async function runThreatAnalysis(url, options, targetLabel) {
  const wrap = document.getElementById('threat-result-wrap');
  const loading = document.getElementById('threat-loading');
  const unavailable = document.getElementById('threat-unavailable');
  const result = document.getElementById('threat-result');
  if (!wrap) return;

  wrap.classList.remove('hidden');
  loading.classList.remove('hidden');
  unavailable.classList.add('hidden');
  result.classList.add('hidden');
  if (window.SoundFX) window.SoundFX.scan();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  const fetchOpts = Object.assign({ signal: controller.signal }, options);

  try {
    const resp = await fetch(url, fetchOpts);
    const data = await resp.json();
    clearTimeout(timer);
    loading.classList.add('hidden');

    if (!data || data.success === false) {
      document.getElementById('threat-unavailable-msg').textContent =
        data && data.error ? data.error : 'The threat-analysis engine could not be reached. Please try again later.';
      unavailable.classList.remove('hidden');
      return;
    }

    lastThreatResult = data;
    renderThreatResult(data, targetLabel);
    addToThreatHistory({
      type: lastThreatRequest ? lastThreatRequest.type : 'url',
      target: targetLabel,
      level: data.threat_level || 'SUSPICIOUS',
      score: data.threat_score != null ? data.threat_score : 0,
      classification: data.classification || '—'
    }, data);

    if (window.SoundFX) {
      const lvl = (data.threat_level || '').toUpperCase();
      if (lvl === 'HIGH RISK' || lvl === 'CRITICAL' || data.is_phishing) window.SoundFX.spam();
      else if (lvl === 'SAFE' || lvl === 'LOW RISK') window.SoundFX.safe();
    }

    result.classList.remove('hidden');
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    clearTimeout(timer);
    loading.classList.add('hidden');
    document.getElementById('threat-unavailable-msg').textContent = 'Threat-analysis request timed out or failed. Please try again.';
    unavailable.classList.remove('hidden');
  }
}

function renderThreatResult(data, targetLabel) {
  const lvl = (data.threat_level || 'SUSPICIOUS').toUpperCase();

  // Score ring
  const score = Math.min(100, Math.max(0, data.threat_score != null ? data.threat_score : 0));
  document.getElementById('threat-score-num').textContent = score;
  const ring = document.getElementById('threat-score-ring');
  ring.className = 'threat-score-ring ' + levelClass(lvl);
  ring.style.setProperty('--score', score + '%');

  // Risk level + classification
  const riskEl = document.getElementById('threat-risk-value');
  riskEl.textContent = lvl;
  riskEl.className = 'threat-risk-value ' + levelClass(lvl);
  document.getElementById('threat-classification').textContent = data.classification || '—';

  // Indicators
  const list = document.getElementById('threat-indicator-list');
  const indicators = data.indicators && data.indicators.length ? data.indicators : [];
  list.innerHTML = indicators.length
    ? indicators.map(i => `<li class="threat-indicator-item bad"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> ${escHtml(i)}</li>`).join('')
    : `<li class="threat-indicator-item good"><svg viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5" width="14" height="14"><polyline points="20 6 9 17 4 12"/></svg> No phishing indicators identified</li>`;

  // Summary
  document.getElementById('threat-summary').textContent = data.summary || 'Analysis complete.';

  // Metric breakdown
  setText('tm-url-rep', data.url_reputation || '—');
  const domainRisk = (data.domain_risk || '—').toUpperCase();
  const domEl = document.getElementById('tm-domain-risk');
  domEl.textContent = domainRisk;
  domEl.className = 'threat-metric-value mono ' + (domainRisk === 'HIGH' ? 'lvl-high' : domainRisk === 'MEDIUM' ? 'lvl-warn' : 'lvl-low');

  const phish = Math.min(100, Math.max(0, data.phishing_probability != null ? data.phishing_probability : 0));
  document.getElementById('tm-phish-bar').style.width = phish + '%';
  document.getElementById('tm-phish-val').textContent = phish + '%';
  setText('tm-content-risk', data.content_risk || '—');
  document.getElementById('tm-score-bar').style.width = score + '%';
  document.getElementById('tm-score-val').textContent = score + '/100';

  // Security alert
  const alertEl = document.getElementById('threat-alert');
  const isDanger = (lvl === 'HIGH RISK' || lvl === 'CRITICAL' || data.is_phishing === true);
  if (isDanger) {
    alertEl.className = 'threat-alert danger';
    alertEl.innerHTML = `<div class="threat-alert-icon">🚨</div>
      <div class="threat-alert-body">
        <div class="threat-alert-title">THREAT DETECTED</div>
        <div class="threat-alert-msg">This content contains indicators commonly associated with phishing or credential theft.</div>
      </div>`;
  } else {
    alertEl.className = 'threat-alert safe';
    alertEl.innerHTML = `<div class="threat-alert-icon">✓</div>
      <div class="threat-alert-body">
        <div class="threat-alert-title">NO IMMEDIATE THREAT DETECTED</div>
        <div class="threat-alert-msg">Current analysis did not identify significant phishing indicators.</div>
      </div>`;
  }
}

function levelClass(lvl) {
  const map = {
    'SAFE': 'lvl-safe',
    'LOW RISK': 'lvl-low',
    'SUSPICIOUS': 'lvl-warn',
    'HIGH RISK': 'lvl-high',
    'CRITICAL': 'lvl-critical'
  };
  return map[lvl] || 'lvl-warn';
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

// ---- Threat history (separate store — email/ML history is never touched) ----
let threatHistory = [];

function loadThreatHistory() {
  try {
    const stored = localStorage.getItem('kavacham_threat_history');
    if (stored) {
      const arr = JSON.parse(stored);
      if (Array.isArray(arr)) threatHistory = arr.slice(0, 60);
    }
  } catch (e) { /* storage unavailable — ignore */ }
}

function saveThreatHistory() {
  try {
    localStorage.setItem('kavacham_threat_history', JSON.stringify(threatHistory.slice(0, 60)));
  } catch (e) { /* storage unavailable — ignore */ }
}

function addToThreatHistory(entry, result) {
  const item = {
    id: generateId(),
    type: 'threat',
    analysis_mode: 'threat',
    threat_kind: entry.type,
    target: entry.target,
    threat_level: entry.level,
    threat_score: entry.score,
    classification: entry.classification,
    timestamp: new Date().toISOString(),
    result: result
  };
  threatHistory.unshift(item);
  if (threatHistory.length > 60) threatHistory = threatHistory.slice(0, 60);
  saveThreatHistory();
  renderThreatHistoryTable();
}

function renderThreatHistoryTable() {
  const body = document.getElementById('threat-history-body');
  const empty = document.getElementById('threat-history-empty');
  if (!body) return;
  if (threatHistory.length === 0) {
    body.innerHTML = '';
    if (empty) empty.style.display = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  const kindIcon = { url: '🔗', file: '📄', message: '💬' };
  body.innerHTML = threatHistory.slice(0, 60).map(t => {
    const lvl = (t.threat_level || 'SUSPICIOUS').toUpperCase();
    return `<tr>
      <td><span class="threat-kind-chip">${kindIcon[t.threat_kind] || '🔍'} ${(t.threat_kind || 'url').toUpperCase()}</span></td>
      <td class="mono" title="${escHtml(t.target || '')}">${escHtml(t.target || '—')}</td>
      <td><span class="risk-badge ${levelClass(lvl)}">${lvl}</span></td>
      <td class="mono">${t.threat_score != null ? t.threat_score : '—'}</td>
      <td>${escHtml(t.classification || '—')}</td>
    </tr>`;
  }).join('');
}

function clearThreatHistory() {
  threatHistory = [];
  saveThreatHistory();
  renderThreatHistoryTable();
  showToast('Threat history cleared.', 'success');
}

function handleThreatAction(action) {
  if (window.SoundFX) window.SoundFX.click();
  if (action === 'block') {
    showToast('🔒 Blocked. Avoid opening this URL/content and do not enter credentials.', 'warning');
  }
}

function addToBrowser() {
  if (window.SoundFX) window.SoundFX.click();
  showToast('Browser Protection is coming soon.', 'info');
}

// Expose for inline handlers
window.navigateTo = navigateTo;
window.toggleSidebar = toggleSidebar;
window.setAnalysisMode = setAnalysisMode;
window.runAnalysis = runAnalysis;
window.clearAnalysis = clearAnalysis;
window.toggleAdvanced = toggleAdvanced;
window.clearHistory = clearHistory;
window.openHistoryDetail = openHistoryDetail;
window.closeModal = closeModal;
window.checkGeminiStatus = checkGeminiStatus;
window.runSingleTestCase = runSingleTestCase;
window.runAllTestSuite = runAllTestSuite;
window.loadTestCaseToAnalyzer = loadTestCaseToAnalyzer;

// Threat Discovery inline handlers
window.analyzeThreatUrl = analyzeThreatUrl;
window.analyzeThreatFile = analyzeThreatFile;
window.analyzeThreatMessage = analyzeThreatMessage;
window.retryLastThreatAnalysis = retryLastThreatAnalysis;
window.checkThreatStatus = checkThreatStatus;
window.clearThreatHistory = clearThreatHistory;
window.handleThreatAction = handleThreatAction;
window.addToBrowser = addToBrowser;
