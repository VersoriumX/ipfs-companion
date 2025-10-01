#!/usr/bin/env node
/**
 * VersoriumX Universal Sentinel – single‑file JavaScript security guard
 *
 * Detects:
 *   • malicious / pirated code (curl/wget → pirate domains, eval, new Function)
 *   • credential leaks (*.pem, *.key, .env writes)
 *   • DoS/DDoS‑prone patterns (infinite loops, zero‑delay timers, un‑throttled HTTP calls)
 *
 * If run inside a Git repo it quarantines offending files in a hidden branch
 * and (optionally) creates a GitHub issue with the warning:
 *   "VersoriumX security Panel has quarantined your activity."
 *
 * No external dependencies – pure Node.js.
 */

'use strict';
const { execSync, spawnSync } = require('child_process');
const { readFileSync, writeFileSync, existsSync, mkdirSync } = require('fs');
const { join, basename } = require('path');
const process = require('process');

// ------------------- Configuration -------------------
const WARNING_MSG = 'VersoriumX security Panel has quarantined your activity.';
const QUARANTINE_BRANCH = 'sentinel/quarantine';

// Regex patterns (JavaScript RegExp objects)
const BAD_PATTERNS = [
  // Piracy / illegal download helpers
  /curl\s+.*\s+https?:\/\/.*(pirate|crack|warez|torrent)/i,
  /wget\s+.*\s+https?:\/\/.*(pirate|crack|warez|torrent)/i,
  // Remote code execution on untrusted input
  /eval$[^)]*$/i,
  /new\s+Function$[^)]*$/i,
  // Network scanning / exfiltration
  /nc\s+.*\s+.*(evil|attacker|scan)/i,
  /nmap\s+.*$/i,
  /ssh\s+.*\s+.*@.*(evil|attacker|malicious)/i,
  // Credential leakage helpers
  /cat\s+.*\.pem/i,
  /cat\s+.*\.key/i,
  /echo\s+.*>\s+.*\.env/i,
  // DoS / DDoS‑prone patterns
  /while\s+true\s*;?\s*do/i,                     // while(true) loops
  /for\s*$\s*;;\s*$/i,                         // for(;;) infinite loop
  /setInterval$[^,]+,\s*0$/i,                  // zero‑delay interval
  /setTimeout$[^,]+,\s*0$/i,                   // zero‑delay timeout
  /http\.get$[^)]*$/i,                         // Node http.get without throttling
  /requests\.get$[^)]*$/i,                     // Python requests.get without timeout
  /urllib\.request\.urlopen$[^)]*$/i,          // Python urllib without timeout
  /socket\.socket$[^)]*$.*listen$[^)]*$/i,   // raw socket listen without backlog
  /net\.createServer/i,                         // Node net.createServer without maxConnections
  /:\s*\\\s*:\s*\\\s*:\s*\\/i                    // classic fork‑bomb pattern
];

// ------------------- Helper Functions -------------------
function log(...args) {
  console.log('[Sentinel]', ...args);
}
function execGit(cmd) {
  return execSync(`git ${cmd}`, { stdio: 'pipe' }).toString().trim();
}
function isGitRepo() {
  try {
    execGit('rev-parse --is-inside-work-tree');
    return true;
  } catch {
    return false;
  }
}
function hasGitHubToken() {
  return !!process.env.GITHUB_TOKEN || !!process.env.GH_TOKEN;
}
function getGitHubToken() {
  return process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
}
function getRepoSlug() {
  const url = execGit('config --get remote.origin.url');
  return url
    .replace(/^git@github\.com:/, '')
    .replace(/^https:\/\/github\.com\//, '')
    .replace(/\.git$/, '');
}
function createOrCheckoutQuarantineBranch() {
  try {
    execGit(`rev-parse --verify ${QUARANTINE_BRANCH}`);
    execGit(`checkout ${QUARANTINE_BRANCH}`);
  } catch {
    execGit(`checkout -b ${QUARANTINE_BRANCH}`);
    try {
      execGit(`push -u origin ${QUARANTINE_BRANCH}`);
    } catch {}
  }
}
function quarantineFile(filePath) {
  createOrCheckoutQuarantineBranch();
  const quarantineDir = 'quarantine';
  if (!existsSync(quarantineDir)) mkdirSync(quarantineDir);
  const dest = join(quarantineDir, basename(filePath));
  execGit(`mv "${filePath}" "${dest}"`);
  execGit(`commit -m "Quarantine ${filePath} – ${WARNING_MSG}"`);
  try {
    execGit(`push origin ${QUARANTINE_BRANCH}`);
  } catch {}
}
function createGitHubIssue(title, body) {
  if (!hasGitHubToken()) {
    log('No GitHub token – skipping issue creation.');
    return;
  }
  const token = getGitHubToken();
  const repo = getRepoSlug();
  const payload = JSON.stringify({ title, body, labels: ['security', 'sentinel'] });
  const curl = spawnSync('curl', [
    '-s', '-X', 'POST',
    '-H', `Authorization: token ${token}`,
    '-H', 'Accept: application/vnd.github+json',
    `https://api.github.com/repos/${repo}/issues`,
    '-d', payload
  ]);
  if (curl.status !== 0) {
    log('Failed to create GitHub issue:', curl.stderr.toString());
  } else {
    log('GitHub issue created:', title);
  }
}

// ------------------- Scanning Logic -------------------
function scanFile(filePath) {
  const content = readFileSync(filePath, 'utf8');
  const matches = [];
  BAD_PATTERNS.forEach((re) => {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      if (re.test(line)) {
        matches.push({ line: idx + 1, text: line.trim(), pattern: re.source });
      }
    });
  });
  return matches;
}

// Walk the directory tree, skipping common binary/ignore folders
function* walk(dir) {
  const entries = require('fs').readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', '.git', '.hg', '.svn'].includes(entry.name)) continue;
      yield* walk(full);
    } else if (entry.isFile()) {
      // Simple binary filter – skip files containing a null byte
      const buf = readFileSync(full);
      if (buf.includes(0)) continue;
      yield full;
    }
  }
}

// ------------------- Main Execution -------------------
(async () => {
  const insideGit = isGitRepo();
  let totalViolations = 0;

  for (const file of walk(process.cwd())) {
    const hits = scanFile(file);
    if (!hits.length) continue;

    totalViolations += hits.length;
    log(`⚠️  ${file} matches ${hits.length} prohibited pattern(s):`);
    hits.forEach((h) => {
      console.log(`  ${file}:${h.line}  ${h.pattern}`);
      console.log(`    → ${h.text}`);
    });

    if (insideGit) {
      quarantineFile(file);
      const issueBody = `${WARNING_MSG}\n\n**File:** \`${file}\`\n**Pattern(s):** ${hits
        .map((h) => '`' + h.pattern + '`')
        .join(', ')}\n\n\`\`\`text\n${hits
        .map((h) => `${file}:${h.line} ${h.text}`)
        .join('\n')}\n\`\`\``;
      createGitHubIssue(`Security Alert – Quarantined ${basename(file)}`, issueBody);
    }
  }

  if (totalViolations > 0) {
    log(`❌ ${totalViolations} violation(s) detected – exiting with error.`);
    process.exit(1);
  } else {
    log('✅ No violations found.');
    process.exit(0);
  }
})(); // <-- close the async IIFE
