/**
 * ============================================================
 *  Scanner Helper — Audit Input Console Test Script
 *
 *  HOW TO USE:
 *    1. Open the Scanner Helper and make sure a session is
 *       active (the scan input must not be greyed out)
 *    2. Tweak the CONFIG block below if needed
 *    3. Paste the whole script into the browser console
 *
 *  The script simulates a human typing into the scan field
 *  and pressing Enter — exactly like a barcode scanner would.
 *  At the end it prints a summary so you can cross-check
 *  the counts shown in the app.
 * ============================================================
 */

(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     CONFIG  —  edit these before running
     ══════════════════════════════════════════════════════════ */
  const CONFIG = {
    // Milliseconds between each simulated scan (e.g. 600 = 0.6s)
    delayBetweenScans: 600,

    // How many scans to run in total.
    // Set to null to run every entry in SCAN_LIST exactly once.
    totalScans: 20,
  };

  /* ══════════════════════════════════════════════════════════
     SCAN LIST
     Each entry has:
       value   — the string the "scanner" sends
       expect  — "valid" | "invalid" | "duplicate"
     ══════════════════════════════════════════════════════════ */
  const SCAN_LIST = [
    // ── VALID barcodes (7 chars, letters + digits) ──────────
    { value: 'AB12345', expect: 'valid'     },
    { value: '12345AB', expect: 'valid'     },
    { value: '123456A', expect: 'valid'     },
    { value: 'ABCDEF1', expect: 'valid'     },
    { value: 'A1B2C3D', expect: 'valid'     },
    { value: 'ZX9876Y', expect: 'valid'     },
    { value: '9A8B7C6', expect: 'valid'     },

    // ── DUPLICATES (repeating earlier valid entries) ─────────
    { value: 'AB12345', expect: 'duplicate' },   // dup of entry 1
    { value: '123456A', expect: 'duplicate' },   // dup of entry 3
    { value: 'ZX9876Y', expect: 'duplicate' },   // dup of entry 6

    // ── INVALID: wrong length ────────────────────────────────
    { value: 'AB1234',   expect: 'invalid'  },   // 6 chars — too short
    { value: '12345',    expect: 'invalid'  },   // 5 chars
    { value: 'AB123456', expect: 'invalid'  },   // 8 chars — too long

    // ── INVALID: all digits, no letters ─────────────────────
    { value: '1234567', expect: 'invalid'   },
    { value: '123456',  expect: 'invalid'   },

    // ── INVALID: all letters, no digits ─────────────────────
    { value: 'ABCDEFG', expect: 'invalid'   },

    // ── INVALID: special characters ─────────────────────────
    { value: 'AB#1234', expect: 'invalid'   },
    { value: 'AB/1234', expect: 'invalid'   },
    { value: 'AB 1234', expect: 'invalid'   },   // space

    // ── INVALID: URL / long garbage (scanner misread) ────────
    { value: 'https://example.com/item?id=ABC123', expect: 'invalid' },
    { value: '(01)AB123', expect: 'invalid' },
  ];

  /* ══════════════════════════════════════════════════════════
     EXPECTED TOTALS  (auto-calculated from the list above)
     ══════════════════════════════════════════════════════════ */
  const list = CONFIG.totalScans !== null
    ? SCAN_LIST.slice(0, CONFIG.totalScans)
    : SCAN_LIST;

  const EXPECTED = {
    total:     list.length,
    valid:     list.filter(s => s.expect === 'valid').length,
    duplicate: list.filter(s => s.expect === 'duplicate').length,
    invalid:   list.filter(s => s.expect === 'invalid').length,
  };

  /* ══════════════════════════════════════════════════════════
     SIMULATOR
     ══════════════════════════════════════════════════════════ */
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  /** Mimics a barcode scanner: fills the input then fires Enter */
  function simulateScan(value) {
    const input = document.getElementById('auditInput');
    if (!input) {
      console.error('[SCAN] #auditInput not found on this page.');
      return false;
    }
    if (input.disabled) {
      console.error('[SCAN] Input is disabled — make sure a session is active first.');
      return false;
    }
    input.value = value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })
    );
    return true;
  }

  async function run() {
    console.group(
      '%c📡 Scanner Helper — Audit Test',
      'font-size:14px;font-weight:bold;color:#00e5ff'
    );

    // ── Pre-flight check ──────────────────────────────────────
    const input = document.getElementById('auditInput');
    if (!input || input.disabled) {
      console.error('❌ No active session detected. Create/select a session in the app first, then re-run.');
      console.groupEnd();
      return;
    }

    // ── Print run plan ────────────────────────────────────────
    console.log(`%c── Run Plan ──────────────────────────────────────────`, 'color:#4a5568');
    console.log(`  Total scans    : ${EXPECTED.total}`);
    console.log(`  Delay between  : ${CONFIG.delayBetweenScans}ms`);
    console.log(`  Est. duration  : ~${((EXPECTED.total * CONFIG.delayBetweenScans) / 1000).toFixed(1)}s\n`);

    console.log(`%c── Expected Results (cross-check these against the app) ─`, 'color:#4a5568');
    console.log(`%c  ✅  Successful scans (Scanned counter) : ${EXPECTED.valid}`,     'color:#39ff14;font-weight:bold');
    console.log(`%c  🔁  Duplicates                         : ${EXPECTED.duplicate}`, 'color:#ff6b35;font-weight:bold');
    console.log(`%c  ❌  Invalid / errors                   : ${EXPECTED.invalid}`,   'color:#ff2d55;font-weight:bold');
    console.log('');

    // ── Snapshot counters before we start ────────────────────
    const getCount = (id) => parseInt(document.getElementById(id)?.textContent || '0', 10);
    const before = {
      valid:     getCount('auditCount'),
      duplicate: getCount('auditDupes'),
      invalid:   getCount('auditErrors'),
    };

    // ── Run the scans ─────────────────────────────────────────
    console.log(`%c── Scanning ─────────────────────────────────────────`, 'color:#4a5568');

    for (let i = 0; i < list.length; i++) {
      const { value, expect } = list[i];
      const num = String(i + 1).padStart(2, '0');

      const ok = simulateScan(value);
      if (!ok) break;

      const expectTag = expect === 'valid' ? '✅' : expect === 'duplicate' ? '🔁' : '❌';
      const truncated = value.length > 30 ? value.slice(0, 27) + '...' : value;
      console.log(`  [${num}/${EXPECTED.total}] ${expectTag} "${truncated}"`);

      if (i < list.length - 1) await delay(CONFIG.delayBetweenScans);
    }

    await delay(200); // let the last scan settle

    // ── Snapshot counters after ───────────────────────────────
    const after = {
      valid:     getCount('auditCount'),
      duplicate: getCount('auditDupes'),
      invalid:   getCount('auditErrors'),
    };

    const got = {
      valid:     after.valid     - before.valid,
      duplicate: after.duplicate - before.duplicate,
      invalid:   after.invalid   - before.invalid,
    };

    // ── Results ───────────────────────────────────────────────
    console.log('');
    console.log(`%c── Results ──────────────────────────────────────────`, 'color:#4a5568');

    const row = (icon, label, expected, actual) => {
      const match = expected === actual;
      const status = match ? '✅ PASS' : '❌ FAIL';
      const color  = match ? '#39ff14' : '#ff2d55';
      console.log(
        `%c  ${status}  ${icon} ${label.padEnd(36)} expected ${expected}  /  got ${actual}`,
        `color:${color}`
      );
    };

    row('✅', 'Successful scans (Scanned counter)',  EXPECTED.valid,     got.valid);
    row('🔁', 'Duplicates',                          EXPECTED.duplicate, got.duplicate);
    row('❌', 'Invalid / errors',                    EXPECTED.invalid,   got.invalid);

    const allPass = got.valid === EXPECTED.valid &&
                    got.duplicate === EXPECTED.duplicate &&
                    got.invalid === EXPECTED.invalid;

    console.log('');
    if (allPass) {
      console.log('%c🎉 All counters match — app is behaving correctly!', 'font-size:13px;font-weight:bold;color:#39ff14');
    } else {
      console.warn('⚠️  One or more counters do not match. Check the Scan Log in the app for details.');
    }

    console.groupEnd();
  }

  run();
})();
