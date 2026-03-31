import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const defaultCorpusRoot = path.join(projectRoot, 'corpus');

const verticals = ['enterprise', 'smb', 'supply-chain', 'medical', 'legal', 'insurance'];
const lanes = ['trusted', 'untrusted'];

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      args[key] = 'true';
      continue;
    }
    args[key] = next;
    index += 1;
  }
  return args;
}

function hasPlaceholder(document) {
  const raw = JSON.stringify(document);
  return /replace-me|replace-with-real-document|replace-with-hostile-source/i.test(raw);
}

function countIndicators(text) {
  return {
    emails: (text.match(/[\w.+-]+@[\w.-]+\.\w+/g) ?? []).length,
    ssns: (text.match(/\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g) ?? []).length,
    accountIds: (text.match(/\b(?:ACCT|ACCOUNT)[-_A-Z0-9]+\b/gi) ?? []).length,
    currency: (text.match(/(?:\$|USD\s?)\d+(?:,\d{3})*(?:\.\d{2})?/gi) ?? []).length,
    hostileMarkers: (
      text.match(/ignore|override|urgent|external|send|export|wire|payment update|system/gi) ?? []
    ).length,
  };
}

async function listFiles(dir) {
  try {
    const entries = await readdir(dir);
    const files = [];
    for (const entry of entries) {
      const fullPath = path.join(dir, entry);
      const entryStat = await stat(fullPath);
      if (entryStat.isFile()) {
        files.push(entry);
      }
    }
    return files;
  } catch {
    return [];
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const corpusRoot = args['corpus-root'] ?? defaultCorpusRoot;
  let failures = 0;

  for (const vertical of verticals) {
    for (const lane of lanes) {
      const laneDir = path.join(corpusRoot, vertical, lane);
      const manifestPath = path.join(laneDir, 'manifest.json');

      let manifest;
      try {
        manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
      } catch {
        console.error(`[FAIL] ${vertical}/${lane} missing or invalid manifest.json`);
        failures += 1;
        continue;
      }

      if (!Array.isArray(manifest.documents) || manifest.documents.length === 0) {
        console.error(`[FAIL] ${vertical}/${lane} has no documents in manifest`);
        failures += 1;
        continue;
      }

      for (const document of manifest.documents) {
        if (hasPlaceholder(document)) {
          console.error(`[FAIL] ${vertical}/${lane} manifest still contains placeholder values`);
          failures += 1;
          break;
        }

        const filePath = path.join(laneDir, document.path);
        try {
          const content = await readFile(filePath, 'utf8');
          const indicators = countIndicators(content);
          const indicatorCount =
            indicators.emails +
            indicators.ssns +
            indicators.accountIds +
            indicators.currency +
            indicators.hostileMarkers;

          if (indicatorCount === 0) {
            console.warn(`[WARN] ${vertical}/${lane}/${document.path} has very low indicator density`);
          } else {
            console.log(
              `[OK] ${vertical}/${lane}/${document.path} | emails=${indicators.emails} ssns=${indicators.ssns} accountIds=${indicators.accountIds} currency=${indicators.currency} hostileMarkers=${indicators.hostileMarkers}`,
            );
          }
        } catch {
          console.error(`[FAIL] ${vertical}/${lane} references missing file: ${document.path}`);
          failures += 1;
        }
      }

      const diskFiles = await listFiles(laneDir);
      const referencedFiles = new Set(manifest.documents.map((document) => document.path));
      const extras = diskFiles.filter(
        (file) => file !== 'manifest.json' && !referencedFiles.has(file),
      );
      if (extras.length > 0) {
        console.warn(`[WARN] ${vertical}/${lane} has unreferenced files: ${extras.join(', ')}`);
      }
    }
  }

  if (failures > 0) {
    process.exitCode = 1;
  }
}

await main();
