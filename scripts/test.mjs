// The unit suite: `npm test`, and the "Run tests" step of the deploy gate.
//
// `node --test` exits 0 when it runs no tests. On the Node 20 runner it could not
// load the .ts test files at all, so it ran none and the gate passed while its log
// said "# tests 0". This runs the same files through node:test's own runner and
// fails unless at least one real test ran and none failed.
import { run } from 'node:test';
import { spec } from 'node:test/reporters';
import { glob } from 'node:fs/promises';
import path from 'node:path';

const PATTERN = 'src/**/*.test.ts';

const files = [];
for await (const f of glob(PATTERN)) files.push(f);
files.sort();
if (files.length === 0) {
  console.error(`No test files match ${PATTERN}; failing rather than passing an empty suite.`);
  process.exit(1);
}

// node:test reports a file that defines no tests as one passing "test" named after
// the file itself. Those are not tests, so they are subtracted from the count.
let placeholders = 0;
let summary = null;
const isPlaceholder = (e) => e.nesting === 0 && e.file && path.resolve(e.name) === e.file;
const stream = run({ files, timeout: 60000 });
stream.on('test:pass', (e) => { if (isPlaceholder(e)) placeholders++; });
stream.on('test:summary', (e) => { if (e.file === undefined) summary = e; });
stream.on('end', () => {
  const ran = summary ? summary.counts.tests - placeholders : 0;
  if (!summary || !summary.success) process.exitCode = 1;
  if (ran <= 0) {
    console.error(`No tests ran (${files.length} file(s) matched ${PATTERN}); failing rather than passing an empty suite.`);
    process.exitCode = 1;
  } else {
    console.log(`Unit tests run: ${ran}`);
  }
});
stream.compose(spec).pipe(process.stdout);
