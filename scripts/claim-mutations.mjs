// Run only from a committed, clean source baseline. Every mutation is built,
// killed by its exact assertion owner, restored byte-for-byte, rebuilt, and
// tested green before the next mutation begins.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);

const build = ['npm', ['run', 'build']];
const unit = (file, title) => [
  'node',
  ['--test', '--test-name-pattern', title, file],
];
const browser = (title) => [
  'npx',
  [
    'playwright',
    'test',
    'e2e/attack.spec.ts',
    '--project=chromium',
    '--grep',
    title,
    '--workers=1',
    '--retries=0',
  ],
];

function run([command, args]) {
  return spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, CI: '1' },
  });
}

function pass(command, label) {
  const result = run(command);
  if (result.status !== 0) {
    throw new Error(`${label}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function distHash() {
  const hash = createHash('sha256');
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else {
        hash.update(path);
        hash.update(readFileSync(path));
      }
    }
  };
  walk('dist');
  return hash.digest('hex');
}

const cases = [
  [
    'query upper bound drops disambiguation',
    'src/attack.ts',
    'worstCase: (256 * BLOCK_SIZE + 2) * blockCount,',
    'worstCase: (256 * BLOCK_SIZE + 0) * blockCount,',
    unit('src/attack.test.ts', 'query estimates include final-byte disambiguation'),
  ],
  [
    'malformed oracle query is counted',
    'src/oracle.ts',
    'if (prevBlock.length !== BLOCK_SIZE || targetBlock.length !== BLOCK_SIZE) {',
    'if (false && (prevBlock.length !== BLOCK_SIZE || targetBlock.length !== BLOCK_SIZE)) {',
    unit('src/oracle.test.ts', 'malformed oracle submissions are rejected'),
  ],
  [
    'unequal XOR input silently truncates',
    'src/oracle.ts',
    'if (a.length !== b.length) {',
    'if (false && a.length !== b.length) {',
    unit('src/oracle.test.ts', 'block and XOR helpers reject malformed lengths'),
  ],
  [
    'UTF-8 byte limit is bypassed',
    'src/input.ts',
    'if (bytes.length > maxBytes) {',
    'if (bytes.length < 0 && bytes.length > maxBytes) {',
    unit('src/input.test.ts', 'demo input limits are enforced on UTF-8 bytes'),
  ],
  [
    'live invalid oracle comparison is not tampered',
    'src/ui.ts',
    'invalidPrev[BLOCK_SIZE - 2] ^= 0x01;',
    'invalidPrev[BLOCK_SIZE - 2] ^= 0x00;',
    browser('Panel 1 live oracle comparison is deterministic'),
  ],
  [
    'editing plaintext unlocks a stale session',
    'src/ui.ts',
    "p2Session = null;\n    runBtn.disabled = true;\n    stopBtn.disabled = true;\n    if (statusEl) statusEl.textContent = 'Plaintext changed",
    "p2Session = null;\n    runBtn.disabled = false;\n    stopBtn.disabled = true;\n    if (statusEl) statusEl.textContent = 'Plaintext changed",
    browser('UTF-8 workload limits and stale-session invalidation'),
  ],
  [
    'block panel counts an unattacked padding block',
    'src/ui.ts',
    'const theoretic = theoreticalQueryCount(BLOCK_SIZE);',
    'const theoretic = theoreticalQueryCount(session.ciphertext.length);',
    browser('Panel 3 recovers the block the learner typed'),
  ],
  [
    'obsolete TLS publication restored',
    'index.html',
    'RFC 9846 (2026)</a>',
    'RFC 8446 (2018)</a>',
    browser('current TLS and CBC remediation claims'),
  ],
  [
    'constant-time padding is called complete',
    'index.html',
    'This reduces one timing signal but is not a complete fix.',
    'This reduces one timing signal and is a complete fix.',
    browser('current TLS and CBC remediation claims'),
  ],
];

const sourceFiles = [...new Set(cases.map((entry) => entry[1]))];
const dirty = spawnSync('git', ['diff', '--exit-code', '--', ...sourceFiles], {
  cwd: root,
  encoding: 'utf8',
});
if (dirty.status !== 0) {
  throw new Error('Commit the source baseline before mutation checks.');
}

pass(build, 'baseline build');
const baseline = distHash();
const evidence = [];
console.log('baseline: unmutated copy PASSES');
mkdirSync('mutation-logs', { recursive: true });

for (const [name, file, before, after, owner] of cases) {
  pass(owner, `${name}: baseline owner`);
  const original = readFileSync(file, 'utf8');
  if (original.split(before).length !== 2) {
    throw new Error(`${name}: expected exactly one mutation site`);
  }

  let mutantHash;
  try {
    writeFileSync(file, original.replace(before, after));
    const sourceDiff = spawnSync('git', ['diff', '--', file], {
      cwd: root,
      encoding: 'utf8',
    }).stdout;
    if (!sourceDiff.trim()) throw new Error(`${name}: source diff is empty`);

    pass(build, `${name}: mutant build`);
    mutantHash = distHash();
    if (mutantHash === baseline) throw new Error(`${name}: production artifact did not move`);

    const result = run(owner);
    writeFileSync(
      `mutation-logs/${name.replaceAll(' ', '-')}.log`,
      result.stdout + result.stderr,
    );
    const output = result.stdout + result.stderr;
    if (
      result.status === 0 ||
      !/AssertionError|ERR_ASSERTION|Error: expect|Expected values|expected/i.test(output)
    ) {
      throw new Error(`${name}: no assertion kill\n${output}`);
    }

    evidence.push({
      name,
      sourceDiff,
      baseline,
      mutant: mutantHash,
      namedTest: owner[1].includes('--grep')
        ? owner[1][owner[1].indexOf('--grep') + 1]
        : owner[1][owner[1].indexOf('--test-name-pattern') + 1],
      assertionFailure: true,
      retries: 0,
    });
  } finally {
    writeFileSync(file, original);
    pass(build, `${name}: restore build`);
    if (distHash() !== baseline) throw new Error(`${name}: restored artifact hash differs`);
    pass(owner, `${name}: restored owner`);
  }

  evidence.at(-1).restoredGreen = true;
  console.log(`${name}: killed; exact artifact restored; owning test green`);
}

writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`all ${cases.length} mutation(s) caught`);
