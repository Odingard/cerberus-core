import { mkdir, access, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const corpusRoot = path.join(projectRoot, 'corpus');

const verticals = ['enterprise', 'smb', 'supply-chain', 'medical'];
const lanes = ['trusted', 'untrusted'];

function manifestTemplate(vertical, lane) {
  return {
    vertical,
    lane,
    documents: [
      {
        path: lane === 'trusted' ? 'replace-with-real-document.txt' : 'replace-with-hostile-source.txt',
        label: lane === 'trusted' ? `${vertical} trusted corpus` : `${vertical} hostile corpus`,
        source: 'replace-me',
        sensitivity: lane === 'trusted' ? 'restricted' : 'hostile',
        notes: 'Replace this placeholder entry with a real or redacted-real document.',
      },
    ],
  };
}

async function ensureMissingFile(filePath, content) {
  try {
    await access(filePath);
  } catch {
    await writeFile(filePath, content, 'utf8');
  }
}

async function main() {
  await mkdir(corpusRoot, { recursive: true });

  for (const vertical of verticals) {
    for (const lane of lanes) {
      const laneDir = path.join(corpusRoot, vertical, lane);
      await mkdir(laneDir, { recursive: true });
      const manifestPath = path.join(laneDir, 'manifest.json');
      await ensureMissingFile(
        manifestPath,
        `${JSON.stringify(manifestTemplate(vertical, lane), null, 2)}\n`,
      );
    }
  }

  console.log(`Corpus scaffold ready at ${corpusRoot}`);
}

await main();
