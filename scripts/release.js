#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

const versionType = process.argv[2] || 'patch';

if (!['patch', 'minor', 'major'].includes(versionType)) {
  console.error('Usage: node release.js [patch|minor|major]');
  console.error('  Default: patch');
  process.exit(1);
}

function bumpVersion(currentVersion, type) {
  const [major, minor, patch] = currentVersion.split('.').map(Number);
  switch (type) {
    case 'major':
      return `${major + 1}.0.0`;
    case 'minor':
      return `${major}.${minor + 1}.0`;
    case 'patch':
      return `${major}.${minor}.${patch + 1}`;
  }
}

function exec(cmd) {
  console.log(`> ${cmd}`);
  return execSync(cmd, { stdio: 'inherit', cwd: rootDir });
}

console.log(`\n🚀 Starting haex-sync-server ${versionType} release...\n`);

// Read current package.json
const packageJsonPath = join(rootDir, 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
const currentVersion = packageJson.version;

if (!currentVersion) {
  console.error('No version found in package.json');
  process.exit(1);
}

const newVersion = bumpVersion(currentVersion, versionType);
console.log(`Bumping version from ${currentVersion} to ${newVersion}`);

// Update package.json
packageJson.version = newVersion;
writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');
console.log('Updated package.json');

// Commit, tag and push
const tagName = `v${newVersion}`;
console.log(`\nCreating release tag: ${tagName}`);

exec(`git add package.json`);
exec(`git commit -m "chore: bump version to ${newVersion}"`);
exec(`git tag ${tagName}`);
exec(`git push`);
exec(`git push origin ${tagName}`);

console.log(`\n✅ Tag ${tagName} pushed`);
console.log('GitHub Actions will now build and push the Docker image.');
