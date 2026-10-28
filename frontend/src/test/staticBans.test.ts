import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

function getAllSourceFiles(dir: string, fileList: string[] = []): string[] {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      if (file !== 'node_modules' && file !== 'dist' && file !== 'test-results') {
        getAllSourceFiles(filePath, fileList);
      }
    } else if (/\.(ts|tsx|html|css)$/.test(file)) {
      fileList.push(filePath);
    }
  }
  return fileList;
}

describe('P12-S3 Static Security Bans & Constraints', () => {
  const srcDir = path.resolve(__dirname, '..');
  const indexHtmlPath = path.resolve(__dirname, '../../index.html');
  const allSrcFiles = getAllSourceFiles(srcDir).filter((f) => f !== __filename);
  const prodCodeFiles = allSrcFiles.filter(
    (f) => !f.endsWith('.test.ts') && !f.endsWith('.test.tsx') && !f.includes('/test/')
  );

  it('prohibits dangerouslySetInnerHTML repo-wide in all src files', () => {
    for (const file of allSrcFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      expect(
        content.includes('dangerouslySetInnerHTML'),
        `Forbidden dangerouslySetInnerHTML found in ${file}`
      ).toBe(false);
    }
  });

  it('prohibits eval() in all src files', () => {
    for (const file of allSrcFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      expect(/\beval\(/.test(content), `Forbidden eval() found in ${file}`).toBe(false);
    }
  });

  it('prohibits direct innerHTML assignment in production source files', () => {
    for (const file of prodCodeFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      expect(/\.innerHTML\s*=/.test(content), `Forbidden innerHTML assignment in ${file}`).toBe(
        false
      );
    }
  });

  it('prohibits console.log in production source files', () => {
    for (const file of prodCodeFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      expect(/\bconsole\.log\(/.test(content), `Forbidden console.log found in ${file}`).toBe(false);
    }
  });

  it('prohibits banned claim words in production source files', () => {
    const bannedPhrases = [
      'zero leakage',
      'tamper-proof',
      'unhackable',
      'guaranteed safe',
      'proves absence',
      'military-grade',
      '100% safe',
    ];

    for (const file of prodCodeFiles) {
      const content = fs.readFileSync(file, 'utf-8').toLowerCase();
      for (const phrase of bannedPhrases) {
        expect(
          content.includes(phrase),
          `Banned claim word "${phrase}" detected in production file: ${file}`
        ).toBe(false);
      }
    }
  });

  it('validates Content-Security-Policy meta tag in index.html', () => {
    const html = fs.readFileSync(indexHtmlPath, 'utf-8');
    expect(html).toContain('http-equiv="Content-Security-Policy"');
    expect(html).toContain("default-src 'self'");
    expect(html).toContain("img-src 'self' data:");
    expect(html).toContain("connect-src 'self'");
  });
});
