/**
 * ANVESHAK AI - Premium 3D Interactive Intelligence Engine
 *
 * UNIQUE FEATURES:
 * 1. THREAT RADAR - Live animated radar sweep showing inbox threat level
 * 2. TOKEN EXPLOSION VISUALIZER - Spam keywords explode out as floating tags when analyzed
 * 3. LIVE TYPE-ANALYZE STREAM - Real-time character analysis with token scoring stream
 *
 * ENHANCED 3D:
 * - Deep 3D particle constellation with Z-depth simulation and mouse parallax
 * - Glowing neon tilt cards with perspective physics
 * - Holographic card shimmer effect
 * - Animated scanning loading states
 * - Animated stat counters
 */

document.addEventListener("DOMContentLoaded", () => {

    // =========================================================================
    // 1. 3D NEURAL PARTICLE NETWORK + ANIMATED CANVAS
    // =========================================================================
    const canvas = document.getElementById("bg-canvas");
    if (canvas) {
        const ctx = canvas.getContext("2d");
        let W, H;
        let mouseX = 0, mouseY = 0;
        let mouseInfluence = { x: 0, y: 0 };
        const PARTICLE_COUNT = 90;

        function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
        window.addEventListener("resize", resize);
        resize();

        class Particle {
            constructor() { this.reset(true); }

            reset(initial = false) {
                this.x = Math.random() * W;
                this.y = initial ? Math.random() * H : H + 10;
                this.z = Math.random() * 800 + 100;
                this.baseX = this.x;
                this.baseY = this.y;
                this.vx = (Math.random() - 0.5) * 0.5;
                this.vy = (Math.random() - 0.5) * 0.5;
                this.vz = (Math.random() - 0.5) * 0.4;
                this.radius = Math.random() * 1.8 + 0.6;
                this.hue = Math.random() > 0.5 ? 240 : 195; // indigo or cyan
                this.life = 1;
            }

            update() {
                this.x += this.vx + mouseInfluence.x * 0.008;
                this.y += this.vy + mouseInfluence.y * 0.008;
                this.z += this.vz;
                if (this.x < 0) this.x = W;
                if (this.x > W) this.x = 0;
                if (this.y < -20) this.y = H;
                if (this.y > H + 20) this.y = 0;
                if (this.z < 80 || this.z > 900) this.vz *= -1;
            }

            draw() {
                const scale = 280 / this.z;
                const px = (this.x - W / 2) * scale + W / 2 + mouseInfluence.x * 0.02 * scale;
                const py = (this.y - H / 2) * scale + H / 2 + mouseInfluence.y * 0.02 * scale;
                const alpha = Math.min(0.9, Math.max(0.05, (900 - this.z) / 800));
                const r = this.radius * scale;

                // Glow effect
                ctx.beginPath();
                ctx.arc(px, py, r * 3, 0, Math.PI * 2);
                ctx.fillStyle = `hsla(${this.hue}, 80%, 60%, ${alpha * 0.05})`;
                ctx.fill();

                ctx.beginPath();
                ctx.arc(px, py, r, 0, Math.PI * 2);
                ctx.fillStyle = `hsla(${this.hue}, 80%, 70%, ${alpha * 0.9})`;
                ctx.fill();

                return { px, py, scale, alpha };
            }
        }

        const particles = Array.from({ length: PARTICLE_COUNT }, () => new Particle());

        // Smooth mouse tracking
        window.addEventListener("mousemove", (e) => {
            mouseX = e.clientX; mouseY = e.clientY;
        });

        function animateCanvas() {
            ctx.clearRect(0, 0, W, H);

            // Smooth mouse influence interpolation
            mouseInfluence.x += ((mouseX - W / 2) - mouseInfluence.x) * 0.04;
            mouseInfluence.y += ((mouseY - H / 2) - mouseInfluence.y) * 0.04;

            const positions = particles.map(p => {
                p.update();
                return p.draw();
            });

            // Neural network connections
            for (let i = 0; i < particles.length; i++) {
                for (let j = i + 1; j < particles.length; j++) {
                    const dx = positions[i].px - positions[j].px;
                    const dy = positions[i].py - positions[j].py;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < 140) {
                        const alpha = (1 - dist / 140) * 0.18 * Math.min(positions[i].alpha, positions[j].alpha);
                        const hue = (particles[i].hue + particles[j].hue) / 2;
                        ctx.beginPath();
                        ctx.moveTo(positions[i].px, positions[i].py);
                        ctx.lineTo(positions[j].px, positions[j].py);
                        ctx.strokeStyle = `hsla(${hue}, 80%, 65%, ${alpha})`;
                        ctx.lineWidth = 0.8;
                        ctx.stroke();
                    }
                }
            }

            requestAnimationFrame(animateCanvas);
        }
        animateCanvas();
    }

    // =========================================================================
    // 2. 3D TILT CARD PHYSICS
    // =========================================================================
    function initTilt(cards) {
        cards.forEach(card => {
            card.addEventListener("mousemove", (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                const rotX = ((y - rect.height / 2) / rect.height) * -8;
                const rotY = ((x - rect.width / 2) / rect.width) * 8;
                card.style.transform = `perspective(1000px) rotateX(${rotX}deg) rotateY(${rotY}deg) translateY(-3px)`;
            });
            card.addEventListener("mouseleave", () => {
                card.style.transform = "perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0)";
            });
        });
    }
    initTilt(document.querySelectorAll(".tilt-card"));

    // =========================================================================
    // FEATURE 1: THREAT RADAR
    // =========================================================================
    const radarCanvas = document.getElementById("threat-radar-canvas");
    if (radarCanvas) {
        const rctx = radarCanvas.getContext("2d");
        const RC = 110; // canvas side
        radarCanvas.width = RC * 2; radarCanvas.height = RC * 2;
        const cx = RC, cy = RC;
        let angle = 0;
        let threatLevel = 0;
        let targetThreat = 0;
        let blips = [];

        window.setRadarThreat = function(level) { // 0-100
            targetThreat = Math.max(0, Math.min(100, level));
            // Generate blips proportional to threat
            blips = [];
            const count = Math.floor(level / 15);
            for (let i = 0; i < count; i++) {
                const a = Math.random() * Math.PI * 2;
                const r = (20 + Math.random() * 75);
                blips.push({ a, r, age: Math.random() * 60, color: level > 50 ? '#ef4444' : '#06b6d4' });
            }
        };

        function drawRadar() {
            rctx.clearRect(0, 0, RC * 2, RC * 2);
            threatLevel += (targetThreat - threatLevel) * 0.03;

            // Threat color interpolation
            const threatColor = `hsl(${120 - threatLevel * 1.2}, 80%, 55%)`;

            // Grid rings
            [25, 50, 75, 100].forEach(r => {
                rctx.beginPath();
                rctx.arc(cx, cy, r, 0, Math.PI * 2);
                rctx.strokeStyle = `rgba(99, 102, 241, ${0.12 + (r === 100 ? 0.1 : 0)})`;
                rctx.lineWidth = r === 100 ? 1.5 : 1;
                rctx.stroke();
            });

            // Cross lines
            rctx.strokeStyle = 'rgba(99, 102, 241, 0.15)';
            rctx.lineWidth = 1;
            [0, 1, 2, 3].forEach(i => {
                const a = (i / 4) * Math.PI * 2;
                rctx.beginPath();
                rctx.moveTo(cx, cy);
                rctx.lineTo(cx + Math.cos(a) * 100, cy + Math.sin(a) * 100);
                rctx.stroke();
            });

            // Radar sweep gradient
            const sweepGrad = rctx.createConicalGradient ? null : null;
            // Sweep sector
            rctx.save();
            rctx.translate(cx, cy);
            rctx.rotate(angle);
            const sweep = rctx.createLinearGradient(0, 0, 100, 0);
            sweep.addColorStop(0, `${threatColor.replace('hsl', 'hsla').replace(')', ', 0.5)')}`.replace('hsla', 'hsla'));

            const grad2 = rctx.createLinearGradient(0, -100, 100, 100);
            grad2.addColorStop(0, 'transparent');
            grad2.addColorStop(0.7, `rgba(${threatLevel > 50 ? '239,68,68' : '99,102,241'}, 0.08)`);
            grad2.addColorStop(1, `rgba(${threatLevel > 50 ? '239,68,68' : '99,102,241'}, 0.25)`);

            rctx.beginPath();
            rctx.moveTo(0, 0);
            rctx.arc(0, 0, 100, -0.6, 0.01);
            rctx.closePath();
            rctx.fillStyle = grad2;
            rctx.fill();

            // Sweep line
            rctx.beginPath();
            rctx.moveTo(0, 0);
            rctx.lineTo(100, 0);
            rctx.strokeStyle = `rgba(${threatLevel > 50 ? '239,68,68' : '6,182,212'}, 0.9)`;
            rctx.lineWidth = 1.5;
            rctx.stroke();

            rctx.restore();

            // Blips
            blips.forEach(b => {
                b.age++;
                const fadeOut = Math.max(0, 1 - (b.age % 80) / 80);
                const bx = cx + Math.cos(b.a) * b.r;
                const by = cy + Math.sin(b.a) * b.r;
                rctx.beginPath();
                rctx.arc(bx, by, 3, 0, Math.PI * 2);
                rctx.fillStyle = b.color.replace(')', `, ${fadeOut})`).replace('rgb', 'rgba');
                rctx.fill();
                // Ring pulse
                rctx.beginPath();
                rctx.arc(bx, by, 3 + (b.age % 30) * 0.3, 0, Math.PI * 2);
                rctx.strokeStyle = b.color.replace(')', `, ${fadeOut * 0.4})`).replace('rgb', 'rgba');
                rctx.lineWidth = 1;
                rctx.stroke();
            });

            // Center dot
            rctx.beginPath();
            rctx.arc(cx, cy, 3, 0, Math.PI * 2);
            rctx.fillStyle = `rgba(${threatLevel > 50 ? '239,68,68' : '6,182,212'}, 0.9)`;
            rctx.fill();

            // Threat level text
            rctx.fillStyle = `rgba(${threatLevel > 50 ? '239,68,68' : '99,102,241'}, 0.9)`;
            rctx.font = `bold 13px monospace`;
            rctx.textAlign = 'center';
            rctx.fillText(`${Math.round(threatLevel)}%`, cx, cy - 70);

            rctx.fillStyle = 'rgba(148,163,184, 0.6)';
            rctx.font = `10px monospace`;
            rctx.fillText('THREAT', cx, cy - 57);

            angle += 0.025;
            requestAnimationFrame(drawRadar);
        }
        drawRadar();
    }

    // =========================================================================
    // FEATURE 2: TOKEN EXPLOSION VISUALIZER
    // =========================================================================
    window.triggerTokenExplosion = function(tokens, isSpam) {
        const container = document.getElementById("token-explosion-zone");
        if (!container) return;
        container.innerHTML = '';
        container.style.display = 'flex';
        container.style.flexWrap = 'wrap';
        container.style.gap = '6px';
        container.style.justifyContent = 'center';

        tokens.forEach((token, i) => {
            const tag = document.createElement("span");
            tag.className = `wc-tag ${isSpam ? 'spam-tag' : ''} token-burst`;
            tag.style.setProperty('--tx', `${(Math.random() - 0.5) * 30}px`);
            tag.style.setProperty('--ty', `${(Math.random() - 0.5) * 20}px`);
            tag.style.animationDelay = `${i * 0.07}s`;
            tag.style.fontSize = `${10 + Math.random() * 5}px`;
            tag.textContent = token;
            container.appendChild(tag);
        });
    };

    // =========================================================================
    // FEATURE 3: LIVE TYPE-ANALYZE STREAM
    // Live streaming analysis updates as user types (debounced 700ms)
    // =========================================================================
    const streamOutput = document.getElementById("live-stream-output");
    let streamTimer = null;

    function runLiveStream(text) {
        if (!streamOutput || !text || text.length < 5) return;
        const words = text.toLowerCase().replace(/[^a-z\s]/g, '').split(/\s+/).filter(w => w.length > 2);
        if (words.length === 0) return;

        const spamIndicators = ['free', 'win', 'prize', 'click', 'urgent', 'claim', 'cash', 'offer',
            'congratulations', 'reward', 'limited', 'exclusive', 'selected', 'verify', 'account', 'suspended'];
        const hamIndicators = ['meeting', 'notes', 'class', 'assignment', 'schedule', 'dinner', 'family',
            'project', 'review', 'please', 'thanks', 'confirm', 'discuss'];

        let html = '';
        words.forEach(w => {
            const isSpamWord = spamIndicators.includes(w);
            const isHamWord = hamIndicators.includes(w);
            if (isSpamWord) {
                html += `<span class="inline-block px-1 rounded text-red-300 bg-red-950/50 border border-red-800/40 text-[11px] font-mono mr-1 mb-1">${w}</span>`;
            } else if (isHamWord) {
                html += `<span class="inline-block px-1 rounded text-emerald-300 bg-emerald-950/40 border border-emerald-800/30 text-[11px] font-mono mr-1 mb-1">${w}</span>`;
            } else {
                html += `<span class="inline-block text-slate-400 text-[11px] font-mono mr-1 mb-1">${w}</span>`;
            }
        });
        streamOutput.innerHTML = html;
    }

    // =========================================================================
    // CHAR COUNTER + LIVE STREAM ATTACH
    // =========================================================================
    const messageInput = document.getElementById("message-input");
    const checkBtn = document.getElementById("check-btn");
    const charCounter = document.getElementById("char-counter");

    function updateCharCount() {
        if (!messageInput || !charCounter) return;
        const count = messageInput.value.length;
        charCounter.textContent = `${count} chars`;
        const hasText = count > 0;
        if (checkBtn) {
            if (hasText) {
                checkBtn.removeAttribute("disabled");
                checkBtn.classList.remove("opacity-50", "cursor-not-allowed");
            } else {
                checkBtn.setAttribute("disabled", "true");
                checkBtn.classList.add("opacity-50", "cursor-not-allowed");
            }
        }

        // Live stream
        clearTimeout(streamTimer);
        streamTimer = setTimeout(() => runLiveStream(messageInput.value), 600);
    }

    if (messageInput) {
        messageInput.addEventListener("input", updateCharCount);
        messageInput.addEventListener("keydown", (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") handlePrediction();
        });
        updateCharCount();
    }

    // Sample buttons
    document.querySelectorAll(".sample-msg-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const sample = btn.getAttribute("data-sample");
            if (messageInput && sample) {
                messageInput.value = sample;
                updateCharCount();
                messageInput.focus();
            }
        });
    });

    // =========================================================================
    // PREDICTION ENGINE
    // =========================================================================
    if (checkBtn) {
        checkBtn.addEventListener("click", handlePrediction);
    }

    async function handlePrediction() {
        const text = messageInput ? messageInput.value.trim() : '';
        if (!text) return;

        const resultSection = document.getElementById("result-section");
        const loadingState = document.getElementById("loading-state");
        const resultCard = document.getElementById("result-card");

        if (resultSection) resultSection.classList.remove("hidden");
        if (loadingState) loadingState.classList.remove("hidden");
        if (resultCard) resultCard.classList.add("hidden");

        if (checkBtn) {
            checkBtn.disabled = true;
            checkBtn.innerHTML = `<svg class="animate-spin w-4 h-4 mr-2 inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"/></svg> Analyzing...`;
        }

        try {
            const response = await fetch("/predict", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: text })
            });
            const data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.error || "Prediction failed");

            renderResult(data, text);
            saveHistory(text, data.prediction, data.confidence);

        } catch (err) {
            alert(`Prediction error: ${err.message}`);
            if (resultSection) resultSection.classList.add("hidden");
        } finally {
            if (loadingState) loadingState.classList.add("hidden");
            if (checkBtn) {
                checkBtn.disabled = false;
                checkBtn.innerHTML = `<svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Analyze Message`;
            }
        }
    }

    function renderResult(data, text) {
        const resultCard = document.getElementById("result-card");
        const resultStatus = document.getElementById("result-status");
        const resultIcon = document.getElementById("result-icon");
        const resultConfidence = document.getElementById("result-confidence");
        const confidenceBar = document.getElementById("confidence-bar");
        const resultExplanation = document.getElementById("result-explanation");
        const keywordsContainer = document.getElementById("keywords-container");
        const keywordsList = document.getElementById("keywords-list");

        if (!resultCard) return;
        resultCard.classList.remove("hidden");
        resultCard.classList.add("result-entrance");

        const isSpam = data.prediction === "Spam";
        const color = isSpam ? "red" : "emerald";

        resultCard.className = `result-entrance p-6 rounded-2xl glass-panel border border-${color}-500/40 bg-gradient-to-br from-${color}-950/30 to-slate-900/90`;

        if (resultStatus) {
            resultStatus.textContent = isSpam ? "⚠ Spam Detected" : "✓ Legitimate — Not Spam";
            resultStatus.className = `text-xl font-bold text-${color}-400`;
        }
        if (resultIcon) {
            resultIcon.innerHTML = `<div class="w-12 h-12 rounded-xl bg-${color}-500/15 border border-${color}-500/40 flex items-center justify-center text-${color}-400 text-2xl">${isSpam ? '⚠' : '✓'}</div>`;
        }
        if (resultConfidence) {
            resultConfidence.textContent = `${data.confidence.toFixed(2)}%`;
            resultConfidence.className = `text-2xl font-black font-mono text-${color}-400`;
        }
        if (confidenceBar) {
            confidenceBar.style.width = '0%';
            confidenceBar.className = `h-2.5 rounded-full progress-bar-fill bg-gradient-to-r from-${color}-500 to-${color === 'red' ? 'rose' : 'teal'}-400`;
            setTimeout(() => { confidenceBar.style.width = `${Math.min(100, data.confidence)}%`; }, 80);
        }
        if (resultExplanation) resultExplanation.textContent = data.explanation || '';

        // Render Structured Influential Signals
        const signalsContainer = document.getElementById("influential-signals-container");
        const signalsList = document.getElementById("influential-signals-list");
        const signals = data.influential_signals || [];

        if (signalsContainer && signalsList) {
            if (signals.length > 0) {
                signalsContainer.classList.remove("hidden");
                signalsList.innerHTML = signals.map(sig => {
                    let badgeClass = "bg-slate-800 text-slate-300 border-slate-700";
                    let dotColor = "bg-slate-400";
                    if (sig.status.includes("Spam")) {
                        badgeClass = "bg-red-950/80 text-red-300 border-red-800/60";
                        dotColor = "bg-red-400";
                    } else if (sig.status.includes("Safe") || sig.status.includes("Ham")) {
                        badgeClass = "bg-emerald-950/80 text-emerald-300 border-emerald-800/60";
                        dotColor = "bg-emerald-400";
                    }
                    return `
                        <div class="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
                            <div class="flex items-center gap-2">
                                <span class="w-2 h-2 rounded-full ${dotColor}"></span>
                                <code class="mono text-indigo-200 font-semibold">${sig.token}</code>
                            </div>
                            <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${badgeClass}">
                                ${sig.status}
                            </span>
                        </div>
                    `;
                }).join('');
            } else {
                signalsContainer.classList.add("hidden");
            }
        }

        // Trigger token explosion feature with clean tokens
        const kws = data.matched_keywords || [];
        if (kws.length > 0 && window.triggerTokenExplosion) {
            window.triggerTokenExplosion(kws, isSpam);
        }

        // Update threat radar based on spam probability
        if (window.setRadarThreat) {
            window.setRadarThreat(isSpam ? data.confidence : (100 - data.confidence));
        }

        resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    // =========================================================================
    // ANIMATED STAT COUNTERS
    // =========================================================================
    function animateCounter(el, target, suffix = '') {
        if (!el) return;
        let start = 0;
        const duration = 900;
        const step = (timestamp) => {
            if (!start) start = timestamp;
            const progress = Math.min((timestamp - start) / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);
            el.textContent = (target % 1 === 0 ? Math.round(ease * target) : (ease * target).toFixed(2)) + suffix;
            if (progress < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    }

    document.querySelectorAll("[data-count]").forEach(el => {
        const target = parseFloat(el.getAttribute("data-count"));
        const suffix = el.getAttribute("data-suffix") || '';
        animateCounter(el, target, suffix);
    });

    // =========================================================================
    // LOCAL STORAGE HISTORY
    // =========================================================================
    const HIST_KEY = 'anveshak_history';
    function getHistory() { try { return JSON.parse(localStorage.getItem(HIST_KEY)) || []; } catch { return []; } }
    function saveHistory(msg, pred, conf) {
        const h = getHistory();
        h.unshift({ msg: msg.length > 80 ? msg.slice(0, 80) + '...' : msg, fullMsg: msg, pred, conf, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
        if (h.length > 12) h.pop();
        localStorage.setItem(HIST_KEY, JSON.stringify(h));
        renderHistory();
    }
    function renderHistory() {
        const list = document.getElementById("history-list");
        const empty = document.getElementById("empty-history");
        if (!list) return;
        const h = getHistory();
        if (h.length === 0) {
            if (empty) empty.classList.remove("hidden");
            list.innerHTML = '';
            return;
        }
        if (empty) empty.classList.add("hidden");
        list.innerHTML = h.map(item => {
            const isSpam = item.pred === 'Spam';
            return `<div class="p-3 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 flex items-center gap-3 cursor-pointer group transition" onclick="document.getElementById('message-input').value=${JSON.stringify(item.fullMsg)};document.getElementById('message-input').dispatchEvent(new Event('input'))">
                <span class="w-2 h-2 rounded-full flex-shrink-0 ${isSpam ? 'bg-red-400' : 'bg-emerald-400'}"></span>
                <span class="text-xs text-slate-300 truncate flex-1 group-hover:text-white">${item.msg.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</span>
                <span class="text-[10px] px-2 py-0.5 rounded font-medium ${isSpam ? 'bg-red-950 text-red-300 border border-red-800/40' : 'bg-emerald-950 text-emerald-300 border border-emerald-800/40'}">${item.pred} ${item.conf}%</span>
                <span class="text-[10px] text-slate-500 font-mono">${item.time}</span>
            </div>`;
        }).join('');
    }

    const clearHistBtn = document.getElementById("clear-history-btn");
    if (clearHistBtn) clearHistBtn.addEventListener("click", () => { localStorage.removeItem(HIST_KEY); renderHistory(); });

    renderHistory();
});
