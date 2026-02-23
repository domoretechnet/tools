// ═══════════════════════════════════════════════════════════════════
//  ASSET SALE LISTER — Fake Scanner Console Script v2
//
//  Paste this entire block into browser DevTools console (F12).
//  Make sure a PALLET is selected and a PRESET is active first.
//
//  CHAOS MODE: randomly injects dupes, bad barcodes, URLs, and
//  garbage strings to exercise validation and error handling.
// ═══════════════════════════════════════════════════════════════════

(async function () {

  // ── Config ───────────────────────────────────────────────────────
  // Tweak these if you want to change chaos frequency
  const CHAOS_RATE      = 0.20;  // 20% of scans will be a chaos event
  const DUPE_RATE       = 0.40;  // of chaos events: 40% chance = dupe repeat
  const INVALID_RATE    = 0.60;  // of chaos events: 60% chance = garbage input

  // Pool of "garbage" values that look like real-world wrong scans
  const GARBAGE_ASSET = [
    'https://www.dell.com/support/home',
    'ASSET-TAG-MISSING',
    '$$ABCD',
    '12345',          // only 5 digits — too short
    '1234567',        // 7 digits — too long
    'ABC123',         // letters in asset (invalid now — digits only)
    '      ',         // whitespace
    'NULL',
    '00000000000000000000', // way too long
    'https://amzn.to/3xFake',
    'RECYCLED',
    '123 45',         // space in middle
    'LOT#99',
    'N/A',
  ];

  const GARBAGE_SERIAL = [
    'https://support.microsoft.com/en-us/windows',
    '1234567',        // all digits — no letters
    'ABCDEFG',        // all letters — no digits
    'SN:MISSING',
    '!!!!!!!!',
    '12345',          // too short
    'AB CD 1',        // spaces
    'SERIALNUMBERNOTFOUND',
    'QR-CODE-ERROR',
    'NULL0000',
    '       ',
    'https://www.google.com',
    'N/A12345',       // 8 chars — too long
    'VOID',
  ];
  // ─────────────────────────────────────────────────────────────────

  function randChar(chars) {
    return chars[Math.floor(Math.random() * chars.length)];
  }

  // Asset tag: EXACTLY 6 digits (0–9)
  function makeAssetTag(usedTags) {
    const digits = '0123456789';
    let tag, attempts = 0;
    do {
      tag = Array.from({length: 6}, () => randChar(digits)).join('');
      attempts++;
    } while (usedTags.has(tag) && attempts < 50000);
    usedTags.add(tag);
    return tag;
  }

  // Serial: 7 alphanumeric, must contain ≥1 letter AND ≥1 digit
  function makeSerial(usedSerials) {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits  = '0123456789';
    const all     = letters + digits;
    let serial, attempts = 0;
    do {
      const arr = [
        randChar(letters),
        randChar(digits),
        ...Array.from({length: 5}, () => randChar(all))
      ];
      // Fisher-Yates shuffle
      for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      serial = arr.join('');
      attempts++;
    } while (usedSerials.has(serial) && attempts < 50000);
    usedSerials.add(serial);
    return serial;
  }

  function pickRandom(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  function fireEnter(input) {
    input.dispatchEvent(new Event('input', {bubbles: true}));
    input.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'Enter', code: 'Enter', keyCode: 13,
      bubbles: true, cancelable: true
    }));
  }

  function setVal(input, value) {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    if (setter) setter.set.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event('input', {bubbles: true}));
  }

  function getStatus() {
    const bar = document.getElementById('statusBar');
    const txt = document.getElementById('statusText');
    if (!bar) return {type: 'unknown', msg: ''};
    const type = ['success','error','warn','pair-ready','ready'].find(c => bar.classList.contains(c)) || 'unknown';
    return {type, msg: txt ? txt.textContent : ''};
  }

  // ── Pre-flight ───────────────────────────────────────────────────
  const assetInput  = document.getElementById('assetInput');
  const serialInput = document.getElementById('serialInput');

  if (!assetInput || !serialInput) {
    console.error('❌  Could not find scan inputs. Are you on the Asset Sale Lister page?');
    return;
  }
  if (assetInput.disabled) {
    console.warn('⚠️  Inputs are disabled — select a PALLET and a PRESET before running.');
    return;
  }

  // ── Prompt ───────────────────────────────────────────────────────
  const countRaw = prompt('How many VALID asset pairs to simulate?\n(Chaos events are additional and automatic)', '20');
  if (!countRaw) { console.log('Cancelled.'); return; }
  const targetPairs = parseInt(countRaw.trim(), 10);
  if (isNaN(targetPairs) || targetPairs < 1 || targetPairs > 500) {
    console.error('❌  Enter a number between 1 and 500.');
    return;
  }

  const delayRaw = prompt('Delay between scans (ms)?\nDefault 1200ms = ~realistic scanner pace', '1200');
  const pairDelay = Math.max(400, parseInt(delayRaw, 10) || 1200);
  const halfDelay = Math.floor(pairDelay / 2);

  console.log(`\n🚀  Fake scanner starting`);
  console.log(`    Target valid pairs : ${targetPairs}`);
  console.log(`    Chaos rate         : ${(CHAOS_RATE*100).toFixed(0)}% of events`);
  console.log(`    Delay between scans: ${pairDelay}ms\n`);
  console.log('%c  #    EVENT       ASSET/VALUE       SERIAL/VALUE        RESULT', 'color:#4a5568;font-family:monospace;');

  // Seed used sets from app state to avoid cross-pallet dupes
  const usedTags    = new Set(typeof globalAssetTags    !== 'undefined' ? globalAssetTags    : []);
  const usedSerials = new Set(typeof globalSerials !== 'undefined' ? globalSerials : []);

  // Keep a short history of recently scanned valid tags to replay as dupes
  const recentTags    = [];
  const recentSerials = [];

  let validLogged = 0;
  let chaosErrors = 0;
  let dupesHit    = 0;
  let eventNum    = 0;

  // We loop until we've logged the requested number of VALID pairs
  while (validLogged < targetPairs) {
    eventNum++;
    const isChaos = Math.random() < CHAOS_RATE;

    if (isChaos) {
      // ── CHAOS EVENT ─────────────────────────────────────────────
      const isDupe = Math.random() < DUPE_RATE && recentTags.length > 0;

      if (isDupe) {
        // Replay a previously valid tag (guaranteed dupe)
        const dupeTag    = pickRandom(recentTags);
        const dupeSerial = pickRandom(recentSerials);

        console.log(
          `%c  ${String(eventNum).padStart(3,'0')}  🔁 DUPE       ${dupeTag.padEnd(16)}  ${dupeSerial}`,
          'color:#ffb347;font-family:monospace;'
        );

        assetInput.focus();
        setVal(assetInput, dupeTag);
        await sleep(55);
        fireEnter(assetInput);
        await sleep(halfDelay);

        const s1 = getStatus();
        if (s1.type === 'pair-ready') {
          // asset went through (bypass on?) — also fire dupe serial
          serialInput.focus();
          setVal(serialInput, dupeSerial);
          await sleep(55);
          fireEnter(serialInput);
          await sleep(100);
        }
        dupesHit++;
      } else {
        // Inject garbage into the asset field
        const garbage = pickRandom(GARBAGE_ASSET);
        console.log(
          `%c  ${String(eventNum).padStart(3,'0')}  🗑️  GARBAGE    ${String(garbage).substring(0,16).padEnd(16)}  —`,
          'color:#ff2d55;font-family:monospace;'
        );

        assetInput.focus();
        setVal(assetInput, garbage);
        await sleep(55);
        fireEnter(assetInput);
        chaosErrors++;
        await sleep(halfDelay);

        // 50% chance: also fire garbage serial if asset somehow passed through
        const s = getStatus();
        if (s.type === 'pair-ready') {
          const garbageSerial = pickRandom(GARBAGE_SERIAL);
          console.log(
            `%c  ${String(eventNum).padStart(3,'0')}      └ BAD SERIAL  —                 ${String(garbageSerial).substring(0,16)}`,
            'color:#ff2d55;font-family:monospace;'
          );
          serialInput.focus();
          setVal(serialInput, garbageSerial);
          await sleep(55);
          fireEnter(serialInput);
          chaosErrors++;
          await sleep(halfDelay);
        }
      }

    } else {
      // ── VALID PAIR ───────────────────────────────────────────────
      const tag    = makeAssetTag(usedTags);
      const serial = makeSerial(usedSerials);

      console.log(
        `%c  ${String(eventNum).padStart(3,'0')}  ✅ PAIR       ${tag.padEnd(16)}  ${serial}`,
        'color:#39ff14;font-family:monospace;'
      );

      // Scan asset tag
      assetInput.focus();
      setVal(assetInput, tag);
      await sleep(55);
      fireEnter(assetInput);
      await sleep(halfDelay);

      // Check asset was accepted
      const s1 = getStatus();
      if (s1.type !== 'pair-ready') {
        console.warn(`    ⚠️  Asset not accepted (status: ${s1.type}): ${s1.msg}`);
        await sleep(halfDelay);
        continue;
      }

      // Scan serial
      serialInput.focus();
      setVal(serialInput, serial);
      await sleep(55);
      fireEnter(serialInput);
      await sleep(150);

      const s2 = getStatus();
      if (s2.type === 'success') {
        validLogged++;
        recentTags.push(tag);
        recentSerials.push(serial);
        if (recentTags.length > 20) { recentTags.shift(); recentSerials.shift(); }
      } else {
        console.warn(`    ⚠️  Pair not logged (status: ${s2.type}): ${s2.msg}`);
      }

      if (validLogged < targetPairs) await sleep(halfDelay - 200);
    }
  }

  console.log(`\n${'─'.repeat(70)}`);
  console.log(`✅  Done!`);
  console.log(`   Valid pairs logged : ${validLogged}`);
  console.log(`   Chaos/garbage hits : ${chaosErrors}`);
  console.log(`   Dupe attempts      : ${dupesHit}`);
  console.log(`   Total scan events  : ${eventNum}`);
  console.log(`${'─'.repeat(70)}\n`);

})();
