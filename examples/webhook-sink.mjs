import { mkdir, appendFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

const port = Number(process.argv[2] ?? 7777);
const logPath = path.join(projectRoot, 'test-results', 'webhook-sink.log');

await mkdir(path.dirname(logPath), { recursive: true });

const server = createServer(async (req, res) => {
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, message: 'Cerberus webhook sink ready' }));
    return;
  }

  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const body = Buffer.concat(chunks).toString('utf8');
  const entry = {
    receivedAt: new Date().toISOString(),
    method: req.method,
    url: req.url,
    headers: req.headers,
    body,
  };

  await appendFile(logPath, `${JSON.stringify(entry)}\n`, 'utf8');
  console.log('\n[webhook-sink] received request');
  console.log(`  method: ${req.method}`);
  console.log(`  url: ${req.url}`);
  console.log(`  body: ${body.slice(0, 400)}`);

  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ ok: true }));
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Cerberus webhook sink listening on http://127.0.0.1:${port}`);
  console.log(`Log file: ${logPath}`);
});
