/* ====================================================================
   KAVACHAM AI — Sound & Voice Alert Engine
   --------------------------------------------------------------------
   Synthesized via Web Audio API (no audio files needed) + Web Speech
   API (speechSynthesis) for the voice announcements.

   API:
     SoundFX.click()          → short UI click (Check button press)
     SoundFX.spam()           → alert siren + "Spam detected" (deep voice)
     SoundFX.safe()           → pleasant chime + "Email is safe" (bright voice)
     SoundFX.scan()           → subtle scanning blip (optional, during analysis)

   The AudioContext is created lazily on the first user gesture, so
   autoplay policies are satisfied. All calls are safe no-ops when the
   APIs are unavailable.
   ==================================================================== */
(function () {
  'use strict';

  var ctx = null;

  function getCtx() {
    if (!window.AudioContext && !window.webkitAudioContext) return null;
    if (!ctx) {
      try {
        ctx = new (window.AudioContext || window.webkitAudioContext)();
      } catch (e) {
        return null;
      }
    }
    if (ctx.state === 'suspended') {
      ctx.resume().catch(function () {});
    }
    return ctx;
  }

  // ---- Low-level tone helper ----
  function tone(freq, startAt, duration, type, volume, freqEnd) {
    var ac = getCtx();
    if (!ac) return;
    try {
      var t0 = ac.currentTime + startAt;
      var osc = ac.createOscillator();
      var gain = ac.createGain();
      osc.type = type || 'sine';
      osc.frequency.setValueAtTime(freq, t0);
      if (freqEnd) {
        osc.frequency.exponentialRampToValueAtTime(freqEnd, t0 + duration);
      }
      gain.gain.setValueAtTime(0.0001, t0);
      gain.gain.exponentialRampToValueAtTime(volume || 0.15, t0 + 0.012);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + duration);
      osc.connect(gain);
      gain.connect(ac.destination);
      osc.start(t0);
      osc.stop(t0 + duration + 0.05);
    } catch (e) { /* ignore */ }
  }

  // ---- Click: short, crisp UI keypress ----
  function click() {
    tone(620, 0, 0.06, 'square', 0.05);
    tone(930, 0.02, 0.07, 'square', 0.035);
  }

  // ---- Scan: quick rising blip ----
  function scan() {
    tone(420, 0, 0.12, 'sine', 0.04, 880);
  }

  // ---- Spam alert: two-tone alarm siren ----
  function spam() {
    // Siren: alternating 660/495 Hz sawtooth pulses
    tone(660, 0, 0.16, 'sawtooth', 0.12);
    tone(495, 0.18, 0.16, 'sawtooth', 0.12);
    tone(660, 0.36, 0.16, 'sawtooth', 0.12);
    tone(495, 0.54, 0.16, 'sawtooth', 0.12);
    // Shrill top accent
    tone(990, 0, 0.1, 'square', 0.06);
    tone(990, 0.54, 0.12, 'square', 0.06);
    speak('Attention. Spam detected.', 'spam');
  }

  // ---- Safe alert: pleasant ascending chime ----
  function safe() {
    tone(523.25, 0, 0.14, 'sine', 0.14);     // C5
    tone(659.25, 0.13, 0.14, 'sine', 0.14);  // E5
    tone(783.99, 0.26, 0.22, 'sine', 0.15);  // G5
    tone(1046.5, 0.5, 0.30, 'sine', 0.10);   // C6 sparkle
    speak('Email is safe.', 'safe');
  }

  // ---- Voice announcement with distinct voice profiles ----
  var voiceCache = null;
  function getVoices() {
    if (!('speechSynthesis' in window)) return [];
    if (voiceCache && voiceCache.length) return voiceCache;
    var voices = window.speechSynthesis.getVoices() || [];
    if (voices.length) voiceCache = voices;
    return voices;
  }
  if ('speechSynthesis' in window) {
    window.speechSynthesis.onvoiceschanged = function () {
      voiceCache = window.speechSynthesis.getVoices() || [];
    };
  }

  // Prefer a deep English voice for spam, a bright English voice for safe.
  function pickVoice(kind) {
    var voices = getVoices();
    if (!voices.length) return null;
    var isEn = function (v) { return /^en/i.test(v.lang || ''); };
    var en = voices.filter(isEn);
    var pool = en.length ? en : voices;

    if (kind === 'spam') {
      // Prefer male/GB or low-pitched voices
      var deep = pool.find(function (v) {
        return /Daniel|George|Google UK English Male|Ryan|Alex/i.test(v.name);
      });
      return deep || null;
    }
    // safe: prefer female / US voices
    var bright = pool.find(function (v) {
      return /Samantha|Zira|Google US English|Karen|Moira|Tessa/i.test(v.name);
    });
    return bright || null;
  }

  function speak(text, kind) {
    if (!('speechSynthesis' in window)) return;
    try {
      window.speechSynthesis.cancel();
      var utter = new SpeechSynthesisUtterance(text);
      var voice = pickVoice(kind);
      if (voice) utter.voice = voice;
      if (kind === 'spam') {
        utter.pitch = 0.55;   // deep, authoritative
        utter.rate = 0.98;
        utter.volume = 1;
      } else {
        utter.pitch = 1.3;    // bright, cheerful
        utter.rate = 1.05;
        utter.volume = 0.95;
      }
      window.speechSynthesis.speak(utter);
    } catch (e) { /* ignore */ }
  }

  // ---- Public API ----
  window.SoundFX = {
    click: click,
    scan: scan,
    spam: spam,
    safe: safe,
    _warm: function () { getCtx(); getVoices(); }
  };

  // Warm up on first pointer interaction (autoplay-safe).
  if (typeof document !== 'undefined') {
    var warmed = false;
    var warm = function () {
      if (warmed) return;
      warmed = true;
      window.SoundFX._warm();
    };
    document.addEventListener('pointerdown', warm, { once: true });
    document.addEventListener('keydown', warm, { once: true });
  }
})();