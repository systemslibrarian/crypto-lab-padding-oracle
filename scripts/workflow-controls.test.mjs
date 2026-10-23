import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(new URL('../.github/workflows/pages.yml', import.meta.url), 'utf8');

function job(name) {
  const start = workflow.indexOf(`  ${name}:\n`);
  assert.notEqual(start, -1, `missing ${name} job`);
  const remainder = workflow.slice(start + 1);
  const next = remainder.search(/^  [a-z][a-z0-9-]*:\n/m);
  return next === -1 ? workflow.slice(start) : workflow.slice(start, start + 1 + next);
}

test('repository code runs with read-only contents permission', () => {
  const preJobs = workflow.slice(0, workflow.indexOf('jobs:\n'));
  assert.match(preJobs, /permissions:\n  contents: read/);
  assert.doesNotMatch(preJobs, /(?:pages|id-token|pull-requests|actions): write/);
  for (const name of ['quality', 'compatibility', 'browser', 'mutation', 'build']) {
    assert.doesNotMatch(job(name), /(?:contents|pages|id-token|pull-requests|actions): write/);
  }
});

test('every referenced action is pinned to an immutable commit', () => {
  const uses = [...workflow.matchAll(/uses:\s+([^\s#]+)/g)].map((match) => match[1]);
  assert.ok(uses.length > 0, 'workflow must reference at least one action');
  for (const reference of uses) {
    assert.match(reference, /@[0-9a-f]{40}$/, `${reference} is not pinned to a full commit`);
  }
});

test('primary quality lane performs a clean audited build', () => {
  const quality = job('quality');
  assert.match(quality, /node-version: 24/);
  assert.match(quality, /run: npm ci/);
  assert.match(quality, /run: npm audit --audit-level=high/);
  assert.match(quality, /run: npm run type-check/);
  assert.match(quality, /run: npm test/);
  assert.match(quality, /run: npm run test:workflow/);
  assert.match(quality, /run: npm run build/);
  assert.doesNotMatch(quality, /npm install(?:\s|$)/);
});

test('compatibility covers the adjacent supported Node releases', () => {
  const compatibility = job('compatibility');
  assert.match(compatibility, /node-version: \[22, 26\]/);
  assert.match(compatibility, /run: npm audit --audit-level=high/);
  assert.match(compatibility, /run: npm run type-check/);
  assert.match(compatibility, /run: npm test/);
  assert.match(compatibility, /run: npm run build/);
});

test('browser and mutation gates feed the fail-closed build context', () => {
  const browser = job('browser');
  const mutation = job('mutation');
  const build = job('build');
  assert.match(browser, /needs: \[quality, compatibility\]/);
  assert.match(browser, /run: npm run test:a11y/);
  assert.match(browser, /name: Package the tested site for Pages\n        if: github\.event_name != 'pull_request'/);
  assert.match(mutation, /needs: \[quality, compatibility\]/);
  assert.match(mutation, /run: npm run test:mutations/);
  assert.match(mutation, /mutation-evidence\.json/);
  assert.match(build, /needs: \[quality, compatibility, browser, mutation\]/);
  assert.match(build, /if: \$\{\{ always\(\) \}\}/);
  assert.match(build, /Require every upstream gate to pass/);
  assert.match(build, /if \[ "\$result" != success \]/);
  assert.doesNotMatch(build, /actions\/checkout|npm (?:ci|install)|npm run/);
});

test('deployment authority exists only in the no-checkout deploy job', () => {
  const deploy = job('deploy');
  assert.match(deploy, /if: github\.event_name != 'pull_request'/);
  assert.match(deploy, /needs: \[build, browser\]/);
  assert.match(deploy, /permissions:\n      pages: write\n      id-token: write/);
  assert.doesNotMatch(deploy, /actions\/checkout|npm (?:ci|install)|run: npm/);
});

test('main deployments are never cancelled by a newer run', () => {
  assert.match(workflow, /cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}/);
});

test('Dependabot automation is gated, version-limited, and fail-closed', () => {
  const merge = job('dependabot-auto-merge');
  assert.match(merge, /needs: build/);
  assert.doesNotMatch(merge, /actions\/checkout|npm (?:ci|install)|npm run/);
  assert.match(merge, /update-type == 'version-update:semver-minor'/);
  assert.match(merge, /update-type == 'version-update:semver-patch'/);
  assert.match(merge, /Leave major updates for human review/);
  assert.match(merge, /Reject an unrecognized Dependabot update type/);
  assert.match(merge, /state="\$\(gh pr view/);
  assert.match(merge, /gh workflow run pages\.yml/);
  assert.match(merge, /::error::gate passed/);
  assert.match(merge, /::error::merge landed, but the required deploy workflow did not dispatch/);
  assert.match(merge, /exit 1/);
  assert.doesNotMatch(merge, /\|\|\s*(?:echo|true)|exit 0\s*#.*failed/);
});
