/*
 * security_report.js
 * ==================
 * Security Report UI for the Unified Email Threat Analysis Engine (Task 2).
 *
 * Wires the "Deep Analyze" button on each Gmail inbox card to POST
 * /api/analyze-email and renders the resulting Security Report:
 *   - SPAM/HAM classification (real model output)
 *   - SAFE / SUSPICIOUS / HIGH RISK verdict + evidence-based risk score
 *   - Threats detected, risk factor bars, evidence, optional Ultra AI explanation
 *
 * All dynamic content is written via textContent (never innerHTML with user
 * data), so untrusted email-derived text cannot inject markup.
 */
(function () {
  "use strict";

  var modal = null;
  var analyzeBtn = null;
  var ultraToggle = null;
  var currentEmail = null;

  window.addEventListener("DOMContentLoaded", init);

  function init() {
    modal = document.getElementById("security-modal");
    if (!modal) return;

    analyzeBtn = document.getElementById("security-analyze-btn");
    ultraToggle = document.getElementById("security-ultra-toggle");

    // Event delegation for all "Deep Analyze" buttons on inbox cards
    document.addEventListener("click", function (e) {
      var btn = e.target.closest(".security-analyze-btn");
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      openSecurityModal(btn.getAttribute("data-email-id"));
    });

    // Analyze (re-run) button inside the modal
    if (analyzeBtn) {
      analyzeBtn.addEventListener("click", function () {
        if (currentEmail) runAnalysis(currentEmail);
      });
    }

    var closeBtn = document.getElementById("security-close-btn");
    if (closeBtn) {
      closeBtn.addEventListener("click", function () {
        modal.classList.add("hidden");
      });
      modal.addEventListener("click", function (e) {
        if (e.target === modal) modal.classList.add("hidden");
      });
    }

    if (ultraToggle) {
      ultraToggle.addEventListener("change", function () {
        if (window.SoundFX && window.SoundFX.click) window.SoundFX.click();
      });
    }

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && modal && !modal.classList.contains("hidden")) {
        modal.classList.add("hidden");
      }
    });
  }

  function openSecurityModal(emailId) {
    if (window.SoundFX && window.SoundFX.click) window.SoundFX.click();
    currentEmail = emailId;
    modal.classList.remove("hidden");
    runAnalysis(emailId);
  }

  function runAnalysis(emailId) {
    var body = document.getElementById("security-report-body");
    if (!body) return;

    if (window.SoundFX && window.SoundFX.scan) window.SoundFX.scan();

    // Reset to loading state
    body.innerHTML = "";
    body.appendChild(loadingView());

    if (analyzeBtn) {
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = "Analyzing…";
    }

    fetch("/api/analyze-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message_id: emailId,
        ultra_ai: !!(ultraToggle && ultraToggle.checked)
      })
    })
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        body.innerHTML = "";
        if (analyzeBtn) {
          analyzeBtn.disabled = false;
          analyzeBtn.textContent = "Re-run Analysis";
        }
        if (!data || !data.success) {
          body.appendChild(errorView((data && data.error) || "Analysis failed."));
          return;
        }
        renderReport(body, data);
      })
      .catch(function (err) {
        body.innerHTML = "";
        if (analyzeBtn) {
          analyzeBtn.disabled = false;
          analyzeBtn.textContent = "Re-run Analysis";
        }
        body.appendChild(errorView("Could not reach the analysis engine. Please try again."));
      });
  }

  // ---- DOM helpers (safe — textContent only) ----

  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function loadingView() {
    var wrap = el("div", "flex flex-col items-center justify-center gap-3 py-14 text-indigo-300");
    var spinner = el("div", "w-9 h-9 rounded-full border-2 border-indigo-500/30 border-t-indigo-400 animate-spin");
    wrap.appendChild(spinner);
    wrap.appendChild(el("p", "text-sm font-medium text-slate-300", "Running KAVACHAM AI Unified Threat Analysis…"));
    wrap.appendChild(el("p", "text-[11px] mono text-slate-500", "ML Spam ∕ Phishing ∕ URL ∕ Sender ∕ Headers ∕ Scam ∕ BEC ∕ Attachments ∕ QR ∕ Intel ∕ Risk"));
    return wrap;
  }

  function errorView(message) {
    var wrap = el("div", "p-6 rounded-2xl bg-red-950/50 border border-red-500/40 text-red-200 text-sm flex items-start gap-3");
    wrap.appendChild(el("span", "text-lg", "⚠"));
    var inner = el("div", "");
    inner.appendChild(el("p", "font-bold", "Analysis unavailable"));
    inner.appendChild(el("p", "text-xs text-red-300 mt-1", message || "Please try again."));
    wrap.appendChild(inner);
    return wrap;
  }

  function verdictColor(v) {
    if (v === "HIGH_RISK") return { text: "text-red-300", bg: "bg-red-950/80 border-red-500/50", dot: "bg-red-400", bar: "from-red-500 to-rose-400" };
    if (v === "SUSPICIOUS") return { text: "text-amber-300", bg: "bg-amber-950/80 border-amber-500/50", dot: "bg-amber-400", bar: "from-amber-500 to-orange-400" };
    return { text: "text-emerald-300", bg: "bg-emerald-950/80 border-emerald-500/50", dot: "bg-emerald-400", bar: "from-emerald-500 to-cyan-400" };
  }

  function section(title, hint) {
    var head = el("div", "flex items-center justify-between mb-2");
    head.appendChild(el("div", "text-[11px] mono text-slate-300 font-bold tracking-wider", title));
    if (hint) head.appendChild(el("span", "text-[10px] mono text-slate-500", hint));
    return head;
  }

  function renderReport(body, data) {
    var msg = data.message || {};
    var cls = data.classification || {};
    var sec = data.security || {};
    var factors = data.risk_factors || {};
    var vc = verdictColor(sec.verdict);

    if (window.SoundFX) {
      if (sec.verdict === "SAFE") window.SoundFX.safe();
      else window.SoundFX.spam();
    }

    // ---- Header: sender / subject / date ----
    var header = el("div", "flex items-start justify-between gap-4 pb-4 border-b border-slate-800");
    var hLeft = el("div", "min-w-0");
    hLeft.appendChild(el("div", "text-[10px] mono text-slate-500 tracking-widest", "UNIFIED EMAIL THREAT ANALYSIS"));
    hLeft.appendChild(el("h3", "text-lg font-bold text-white mt-1 break-words", msg.subject || "(No Subject)"));
    hLeft.appendChild(el("p", "text-xs text-slate-400 mt-0.5", msg.sender || "Unknown Sender"));
    hLeft.appendChild(el("p", "text-[11px] font-mono text-slate-500 mt-0.5", msg.date || ""));
    header.appendChild(hLeft);

    var badge = el("span", "px-3 py-1.5 rounded-xl text-xs font-black tracking-wider uppercase mono border " + vc.bg + " " + vc.text + " flex items-center gap-1.5 flex-shrink-0");
    badge.appendChild(el("span", "w-1.5 h-1.5 rounded-full " + vc.dot));
    badge.appendChild(document.createTextNode(sec.verdict || "UNKNOWN"));
    header.appendChild(badge);
    body.appendChild(header);

    // ---- Verdict + risk score ----
    var scoreRow = el("div", "grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4");
    var verdictBox = el("div", "glass-panel rounded-2xl p-4 col-span-1");
    verdictBox.appendChild(el("div", "text-[10px] mono text-slate-500 uppercase tracking-wider", "Security Verdict"));
    verdictBox.appendChild(el("div", "text-2xl font-black " + vc.text + " mt-1", (sec.verdict || "UNKNOWN").replace("_", " ")));
    verdictBox.appendChild(el("p", "text-[11px] text-slate-500 mt-0.5", sec.risk_level || ""));
    scoreRow.appendChild(verdictBox);

    var riskBox = el("div", "glass-panel rounded-2xl p-4");
    riskBox.appendChild(el("div", "text-[10px] mono text-slate-500 uppercase tracking-wider", "Risk Score"));
    riskBox.appendChild(el("div", "text-3xl font-black font-mono text-white", (sec.risk_score !== undefined ? sec.risk_score : "—") + " / 100"));
    var barWrap = el("div", "w-full bg-slate-900/80 rounded-full h-2 overflow-hidden border border-white/5 mt-2");
    var barFill = el("div", "h-2 rounded-full bg-gradient-to-r " + vc.bar, "");
    barFill.style.width = Math.min(100, sec.risk_score || 0) + "%";
    barWrap.appendChild(barFill);
    riskBox.appendChild(barWrap);
    scoreRow.appendChild(riskBox);

    var classBox = el("div", "glass-panel rounded-2xl p-4");
    classBox.appendChild(el("div", "text-[10px] mono text-slate-500 uppercase tracking-wider", "ML Classification"));
    var clsBadge = el("span", "mt-1 inline-flex px-2.5 py-0.5 rounded-lg text-sm font-bold mono border " +
      (cls.label === "SPAM" ? "bg-red-950/80 border-red-500/40 text-red-300" : "bg-emerald-950/80 border-emerald-500/40 text-emerald-300"));
    clsBadge.textContent = cls.label || "—";
    classBox.appendChild(clsBadge);
    classBox.appendChild(el("p", "text-[11px] text-slate-400 mt-1.5", "Confidence: " + (cls.confidence !== undefined ? cls.confidence + "%" : "—") +
      (cls.probability_spam !== undefined ? "  •  P(spam) " + cls.probability_spam + "%" : "")));
    if (cls.decision_threshold) {
      classBox.appendChild(el("p", "text-[10px] mono text-slate-500", "Threshold: " + cls.decision_threshold + "%"));
    }
    scoreRow.appendChild(classBox);
    body.appendChild(scoreRow);

    // ---- Threat intelligence note ----
    if (data.intel_status && !data.intel_status.virustotal_configured) {
      body.appendChild(el("div", "mt-3 p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 text-[10px] mono text-slate-500",
        "Threat intelligence unavailable — VirusTotal API key not configured. Local detection engines remain active."));
    }

    // ---- Risk factor signals ----
    var factorNames = { "url": "URL Risk", "sender": "Sender Risk", "content": "Content Risk", "authentication": "Authentication", "attachment": "Attachment Risk" };
    var factorOrder = ["url", "sender", "content", "authentication", "attachment"];
    var factorBox = el("div", "mt-5");
    factorBox.appendChild(section("Security Signals", "weighted, evidence-based factor scores"));
    var factorList = el("div", "space-y-2");
    factorOrder.forEach(function (key) {
      var val = factors[key] || 0;
      var row = el("div", "");
      var top = el("div", "flex items-center justify-between text-[11px]");
      top.appendChild(el("span", "text-slate-300 font-semibold", factorNames[key] || key));
      top.appendChild(el("span", "text-slate-400 font-mono", val + " / 100"));
      row.appendChild(top);
      var track = el("div", "mt-1 w-full bg-slate-900/80 rounded-full h-1.5 overflow-hidden border border-white/5");
      var fill = el("div", "h-1.5 rounded-full", "");
      fill.style.width = Math.min(100, val) + "%";
      fill.className = "h-1.5 rounded-full bg-gradient-to-r " + fillColor(val);
      track.appendChild(fill);
      row.appendChild(track);
      factorList.appendChild(row);
    });
    factorBox.appendChild(factorList);
    body.appendChild(factorBox);

    // ---- Threats detected ----
    var threats = data.threats || [];
    var threatBox = el("div", "mt-5");
    threatBox.appendChild(section("Threats Detected", threats.length + " flagged signal(s)"));
    if (threats.length === 0) {
      threatBox.appendChild(el("p", "text-xs text-slate-500 p-3 rounded-xl bg-slate-900/40 border border-slate-800/60",
        "No concrete threats were detected across any analysis engine."));
    } else {
      var tList = el("div", "space-y-1.5");
      threats.forEach(function (t) {
        var st = t.severity || "medium";
        var row = el("div", "flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-900/50 border border-slate-800/70");
        row.appendChild(el("span", {
          "critical": "text-red-400",
          "high": "text-red-300",
          "medium": "text-amber-300",
          "low": "text-slate-400"
        }[st] || "text-amber-300", "⚠"));
        var inner = el("div", "min-w-0");
        inner.appendChild(el("p", "text-xs font-bold text-slate-200", t.label || t.type));
        if (t.evidence) inner.appendChild(el("p", "text-[11px] text-slate-400 mt-0.5 leading-relaxed", t.evidence));
        row.appendChild(inner);
        tList.appendChild(row);
      });
      threatBox.appendChild(tList);
    }
    body.appendChild(threatBox);

    // ---- Top reasons ----
    var reasons = data.top_reasons || [];
    if (reasons.length) {
      var reasonBox = el("div", "mt-5");
      reasonBox.appendChild(section("Why This Score", "top contributing evidence"));
      var rList = el("div", "space-y-1.5");
      reasons.forEach(function (r) {
        var row = el("div", "flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-900/40 border border-slate-800/60");
        row.appendChild(el("span", "text-xs text-indigo-300 mono", "▸"));
        var inner = el("div", "min-w-0");
        inner.appendChild(el("p", "text-[11px] text-slate-300 leading-relaxed", r.reason || ""));
        if (r.factor) inner.appendChild(el("p", "text-[10px] mono text-slate-500 mt-0.5", "Factor: " + r.factor.replace("_", " ") + "  •  " + (r.severity || "none")));
        row.appendChild(inner);
        rList.appendChild(row);
      });
      reasonBox.appendChild(rList);
      body.appendChild(reasonBox);
    }

    // ---- Evidence ----
    var evidence = data.evidence || [];
    if (evidence.length) {
      var evBox = el("div", "mt-5");
      evBox.appendChild(section("Evidence", "every detected signal, explained"));
      var evList = el("div", "space-y-1.5");
      evidence.forEach(function (e) {
        var row = el("div", "flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/50");
        row.appendChild(el("span", "text-[10px] mono text-slate-500", e.category || "-"));
        var inner = el("div", "min-w-0");
        inner.appendChild(el("p", "text-[11px] text-slate-400 leading-relaxed", e.evidence || ""));
        inner.appendChild(el("p", "text-[10px] mono text-slate-600 mt-0.5", "type: " + (e.type || "") + "  •  severity: " + (e.severity || "")));
        row.appendChild(inner);
        evList.appendChild(row);
      });
      evBox.appendChild(evList);
      body.appendChild(evBox);
    }

    // ---- URLs ----
    if (data.urls && data.urls.length) {
      var urlBox = el("div", "mt-5");
      urlBox.appendChild(section("URLs Analyzed (" + data.urls.length + ")", "structural inspection" + (data.intel_status && data.intel_status.virustotal_configured ? " + VirusTotal" : "")));
      var urlList = el("div", "space-y-1.5");
      data.urls.forEach(function (u) {
        var row = el("div", "p-2.5 rounded-xl bg-slate-900/40 border border-slate-800/60");
        var head = el("div", "flex items-center justify-between gap-2");
        var riskColor = { "high": "text-red-300", "medium": "text-amber-300", "low": "text-slate-300", "none": "text-emerald-300", "critical": "text-red-400" };
        head.appendChild(el("p", "text-[11px] font-mono text-slate-300 break-all", (u.url || "").slice(0, 120)));
        head.appendChild(el("span", "text-[10px] mono flex-shrink-0 " + (riskColor[u.risk] || "text-slate-400"), (u.risk || "unknown").toUpperCase()));
        row.appendChild(head);
        var meta = el("p", "text-[10px] mono text-slate-500 mt-1");
        meta.textContent = "host: " + (u.hostname || "–") + "   •   " +
          (u.intel_available ? "VirusTotal: " + (u.reputation || "unknown") : "intel: unavailable");
        row.appendChild(meta);
        if (u.findings && u.findings.length) {
          var f = el("p", "text-[10px] text-slate-500 mt-1 leading-relaxed", "• " + u.findings.join(" • "));
          row.appendChild(f);
        }
        urlList.appendChild(row);
      });
      urlBox.appendChild(urlList);
      body.appendChild(urlBox);
    }

    // ---- Attachments ----
    if (data.attachments && data.attachments.length) {
      var attBox = el("div", "mt-5");
      attBox.appendChild(section("Attachments (" + data.attachments.length + ")", "metadata only — files never executed"));
      var attList = el("div", "space-y-1.5");
      data.attachments.forEach(function (a) {
        var row = el("div", "p-2.5 rounded-xl bg-slate-900/40 border border-slate-800/60");
        var head = el("div", "flex items-center justify-between gap-2");
        head.appendChild(el("p", "text-[11px] font-mono text-slate-300 break-all", a.filename || "attachment"));
        head.appendChild(el("span", "text-[10px] mono " + (a.risk === "critical" || a.risk === "high" ? "text-red-300" : a.risk === "medium" ? "text-amber-300" : "text-emerald-300"), (a.risk || "none").toUpperCase()));
        row.appendChild(head);
        var meta = el("p", "text-[10px] mono text-slate-500 mt-1");
        meta.textContent = (a.mime_type || "unknown type") + "  •  " + (a.size || 0) + " bytes  •  sha256: " + (a.sha256 || "unavailable").slice(0, 12) + "…" +
          (a.intel_available ? "  •  VirusTotal: " + (a.reputation || "unknown") : "");
        row.appendChild(meta);
        if (a.risk_reason) row.appendChild(el("p", "text-[10px] text-slate-500 mt-1", a.risk_reason));
        attList.appendChild(row);
      });
      attBox.appendChild(attList);
      body.appendChild(attBox);
    }

    // ---- Sender & header analysis ----
    var secGrid = el("div", "mt-5 grid grid-cols-1 sm:grid-cols-2 gap-3");
    var snd = data.sender_analysis || {};
    var sndBox = el("div", "glass-panel rounded-2xl p-4");
    sndBox.appendChild(el("div", "text-[10px] mono text-slate-500 uppercase tracking-wider", "Sender Analysis"));
    sndBox.appendChild(el("p", "text-[11px] text-slate-300 mt-1.5 leading-relaxed", snd.summary || ""));
    if (snd.indicators && snd.indicators.length) {
      (snd.indicators || []).forEach(function (i) {
        sndBox.appendChild(el("p", "text-[10px] text-slate-400 mt-1", "• " + (i.evidence || "")));
      });
    }
    secGrid.appendChild(sndBox);

    var hdr = data.header_analysis || {};
    var hdrBox = el("div", "glass-panel rounded-2xl p-4");
    hdrBox.appendChild(el("div", "text-[10px] mono text-slate-500 uppercase tracking-wider", "Header Authentication"));
    hdrBox.appendChild(el("p", "text-[11px] text-slate-300 mt-1.5 leading-relaxed", hdr.summary || ""));
    if (hdr.authentication && hdr.authentication.authentication_results) {
      var ar = hdr.authentication.authentication_results;
      var line = el("p", "text-[10px] mono text-slate-400 mt-1.5");
      line.textContent = "SPF: " + (ar.spf || "NONE") + "   DKIM: " + (ar.dkim || "NONE") + "   DMARC: " + (ar.dmarc || "NONE");
      hdrBox.appendChild(line);
    }
    secGrid.appendChild(hdrBox);

    var scm = data.scam_analysis || {};
    var bec = data.bec_analysis || {};
    if (scm.summary || bec.summary) {
      var scmBox = el("div", "glass-panel rounded-2xl p-4");
      scmBox.appendChild(el("div", "text-[10px] mono text-slate-500 uppercase tracking-wider", "Scam / Social Engineering"));
      scmBox.appendChild(el("p", "text-[11px] text-slate-300 mt-1.5 leading-relaxed", scm.summary || "No significant scam indicators."));
      (scm.indicators || []).slice(0, 3).forEach(function (i) {
        scmBox.appendChild(el("p", "text-[10px] text-slate-400 mt-1", "• " + (i.evidence || "")));
      });
      secGrid.appendChild(scmBox);

      var becBox = el("div", "glass-panel rounded-2xl p-4");
      becBox.appendChild(el("div", "text-[10px] mono text-slate-500 uppercase tracking-wider", "BEC / Impersonation"));
      becBox.appendChild(el("p", "text-[11px] text-slate-300 mt-1.5 leading-relaxed", bec.summary || "No BEC indicators."));
      (bec.indicators || []).slice(0, 3).forEach(function (i) {
        becBox.appendChild(el("p", "text-[10px] text-slate-400 mt-1", "• " + (i.evidence || "")));
      });
      secGrid.appendChild(becBox);
    }
    body.appendChild(secGrid);

    // ---- QR analysis ----
    var qr = data.qr_analysis || {};
    if (qr.summary && qr.status === "unavailable") {
      body.appendChild(el("div", "mt-5 p-2.5 rounded-xl bg-slate-900/40 border border-slate-800/60 text-[10px] mono text-slate-500",
        "QR analysis: " + qr.summary));
    }

    // ---- Ultra AI explanation ----
    var ai = data.ai_explanation;
    if (ai && ai.success) {
      var aiBox = el("div", "mt-5 p-4 rounded-2xl bg-indigo-950/50 border border-indigo-500/40");
      var aiHead = el("div", "flex items-center justify-between");
      aiHead.appendChild(el("div", "text-[11px] mono text-indigo-300 font-bold tracking-wider", "KAVACHAM AI PRO — Ultra Explanation"));
      aiHead.appendChild(el("span", "text-[10px] mono text-slate-500", ai.model_used || "gemini"));
      aiBox.appendChild(aiHead);
      aiBox.appendChild(el("p", "text-xs text-slate-200 mt-2 leading-relaxed", ai.explanation || ""));
      if (ai.what_to_verify && ai.what_to_verify.length) {
        aiBox.appendChild(el("div", "text-[10px] mono text-slate-400 mt-3 uppercase tracking-wider", "What to verify"));
        (ai.what_to_verify || []).forEach(function (v) {
          aiBox.appendChild(el("p", "text-[11px] text-slate-300 mt-1", "• " + v));
        });
      }
      if (ai.recommended_actions && ai.recommended_actions.length) {
        aiBox.appendChild(el("div", "text-[10px] mono text-slate-400 mt-3 uppercase tracking-wider", "Recommended actions"));
        (ai.recommended_actions || []).forEach(function (a) {
          aiBox.appendChild(el("p", "text-[11px] text-slate-300 mt-1", "• " + a));
        });
      }
      body.appendChild(aiBox);
    }
  }

  function fillColor(val) {
    if (val >= 61) return "from-red-500 to-rose-400";
    if (val >= 31) return "from-amber-500 to-orange-400";
    return "from-emerald-500 to-cyan-400";
  }
})();