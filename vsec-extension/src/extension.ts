import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import Anthropic from '@anthropic-ai/sdk';

// ── Supported file types ───────────────────────────────────────────────────────
const SUPPORTED = new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.rb', '.go',
  '.java', '.c', '.cpp', '.cs', '.rs', '.sh', '.env',
  '.yml', '.yaml', '.json', '.sql', '.tf',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv',
  'dist', 'build', 'vendor', 'target', '.next',
]);

const SPECIAL_FILES = new Set([
  'dockerfile', '.env', '.env.example', 'requirements.txt',
  'package.json', 'gemfile', 'cargo.toml', 'makefile',
]);

// ── System prompt ──────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `
You are VSec, a senior application security engineer doing a code review.
Analyze the provided source code for security vulnerabilities.

OUTPUT FORMAT — use EXACTLY this structure:

====================================================
VSEC CODE SECURITY REVIEW
====================================================

[EXECUTIVE SUMMARY]
2-3 sentences on overall security posture. Be direct and honest.

[VULNERABILITIES]
One block per vulnerability:

  Vuln #N
  Severity : Critical / High / Medium / Low
  Type     : <SQL Injection / XSS / RCE / Hardcoded Secret / etc>
  File     : <filename:line_number>
  Code     : <the vulnerable snippet>
  Exploit  : <exact proof-of-concept>
  Fix      : <corrected code or mitigation>

[SECURITY MISCONFIGURATIONS]
Config, secrets, dependency issues. Same block format.

[CODE QUALITY & SECURITY IMPROVEMENTS]
Non-critical weaknesses with file references and fixes.

[VERDICT]
Overall risk: Critical / High / Medium / Low
Top 3 immediate fixes.
`;

// ── File collection ────────────────────────────────────────────────────────────
function collectFiles(dirPath: string): { rel: string; content: string }[] {
  const files: { rel: string; content: string }[] = [];

  function walk(current: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const full = path.join(current, entry.name);

      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        const ext  = path.extname(entry.name).toLowerCase();
        const name = entry.name.toLowerCase();
        if (!SUPPORTED.has(ext) && !SPECIAL_FILES.has(name)) continue;
        try {
          const content = fs.readFileSync(full, 'utf8');
          files.push({ rel: path.relative(dirPath, full), content });
        } catch { /* skip */ }
      }
    }
  }

  walk(dirPath);
  return files;
}

// ── Build LLM context ──────────────────────────────────────────────────────────
function buildContext(files: { rel: string; content: string }[], maxChars = 60000): string {
  const parts: string[] = [];
  let total = 0;
  let skipped = 0;

  for (const { rel, content } of files) {
    const snippet = `\n${'='.repeat(50)}\nFILE: ${rel}\n${'='.repeat(50)}\n${content}\n`;
    if (total + snippet.length > maxChars) { skipped++; continue; }
    parts.push(snippet);
    total += snippet.length;
  }

  if (skipped > 0) {
    parts.push(`\n[NOTE: ${skipped} files skipped — context limit reached]`);
  }
  return parts.join('');
}

// ── Quick pattern scan ─────────────────────────────────────────────────────────
function quickScan(files: { rel: string; content: string }[]): string[] {
  const issues: string[] = [];
  const patterns: [string, string[]][] = [
    ['Hardcoded password',  ['password =', 'passwd =', 'pwd =']],
    ['Hardcoded API key',   ['api_key =', 'apikey =', 'api_secret =']],
    ['eval() / exec()',     ['eval(', 'exec(']],
    ['shell=True',          ['shell=True']],
    ['SQL string concat',   ["SELECT * FROM", "+ ' WHERE"]],
    ['Debug mode on',       ['DEBUG = True', 'debug=True', 'DEBUG=True']],
    ['.env exposed',        ['.env']],
  ];

  for (const { rel, content } of files) {
    for (const [label, triggers] of patterns) {
      for (const trigger of triggers) {
        if (content.includes(trigger)) {
          const lineNum = content.split('\n').findIndex(l => l.includes(trigger)) + 1;
          issues.push(`⚠️  ${label} in \`${rel}:${lineNum}\``);
          break;
        }
      }
    }
  }
  return issues;
}

// ── Webview HTML ───────────────────────────────────────────────────────────────
function getWebviewHtml(): string {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    padding: 20px;
    line-height: 1.7;
  }
  #header {
    color: #00ff88;
    font-size: 15px;
    font-weight: bold;
    border-bottom: 1px solid #00ff8833;
    padding-bottom: 12px;
    margin-bottom: 16px;
    letter-spacing: 1px;
  }
  #status {
    color: #58a6ff;
    font-size: 12px;
    margin-bottom: 16px;
    padding: 6px 10px;
    background: #161b22;
    border-left: 3px solid #58a6ff;
    border-radius: 2px;
  }
  #quick-findings {
    margin-bottom: 16px;
    padding: 10px;
    background: #161b22;
    border-left: 3px solid #f0a500;
    border-radius: 2px;
    display: none;
  }
  #quick-findings h4 { color: #f0a500; margin-bottom: 8px; }
  #quick-findings p  { color: #c9d1d9; margin: 3px 0; font-size: 12px; }
  #output {
    white-space: pre-wrap;
    word-break: break-word;
    background: #0d1117;
    padding: 10px 0;
  }
  .sev-critical { color: #ff4444; font-weight: bold; }
  .sev-high     { color: #ff8800; font-weight: bold; }
  .sev-medium   { color: #ffcc00; }
  .sev-low      { color: #58a6ff; }
  .sev-ok       { color: #00ff88; }
  #done-bar {
    margin-top: 16px;
    padding: 8px 12px;
    background: #00ff8811;
    border: 1px solid #00ff8833;
    border-radius: 4px;
    color: #00ff88;
    font-size: 12px;
    display: none;
  }
</style>
</head>
<body>
  <div id="header">⚡ VSec — AI Security Code Review</div>
  <div id="status">Initializing...</div>
  <div id="quick-findings"><h4>⚡ Quick Scan Findings</h4><div id="qf-list"></div></div>
  <div id="output"></div>
  <div id="done-bar"></div>

  <script>
    const output  = document.getElementById('output');
    const status  = document.getElementById('status');
    const qfDiv   = document.getElementById('quick-findings');
    const qfList  = document.getElementById('qf-list');
    const doneBar = document.getElementById('done-bar');

    function colorize(text) {
      return text
        .replace(/Critical/g, '<span class="sev-critical">Critical</span>')
        .replace(/High/g,     '<span class="sev-high">High</span>')
        .replace(/Medium/g,   '<span class="sev-medium">Medium</span>')
        .replace(/Low/g,      '<span class="sev-low">Low</span>');
    }

    window.addEventListener('message', e => {
      const msg = e.data;
      switch (msg.type) {
        case 'status':
          status.textContent = msg.text;
          status.style.borderColor = msg.color || '#58a6ff';
          status.style.color = msg.color || '#58a6ff';
          break;

        case 'quick':
          if (msg.issues && msg.issues.length > 0) {
            qfDiv.style.display = 'block';
            msg.issues.forEach(i => {
              const p = document.createElement('p');
              p.textContent = i;
              qfList.appendChild(p);
            });
          }
          break;

        case 'chunk':
          output.innerHTML = colorize(output.textContent + msg.text);
          window.scrollTo(0, document.body.scrollHeight);
          break;

        case 'done':
          status.textContent = '✔ Review complete';
          status.style.borderColor = '#00ff88';
          status.style.color = '#00ff88';
          doneBar.style.display = 'block';
          doneBar.textContent = '✔ Analysis complete — ' + msg.files + ' file(s) reviewed';
          break;

        case 'error':
          status.textContent = '✗ ' + msg.text;
          status.style.borderColor = '#ff4444';
          status.style.color = '#ff4444';
          break;
      }
    });
  </script>
</body>
</html>`;
}

// ── Core review runner ─────────────────────────────────────────────────────────
async function runReview(targetPath: string, isFolder: boolean, ctx: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration('vsec');
  const apiKey = config.get<string>('anthropicApiKey')
    || process.env.ANTHROPIC_API_KEY
    || '';
  const model  = config.get<string>('model') || 'claude-haiku-4-5';

  if (!apiKey) {
    vscode.window.showErrorMessage(
      'VSec: No API key. Set vsec.anthropicApiKey in Settings or ANTHROPIC_API_KEY env var.'
    );
    return;
  }

  // Create panel
  const panel = vscode.window.createWebviewPanel(
    'vsecReview',
    `VSec — ${path.basename(targetPath)}`,
    vscode.ViewColumn.Beside,
    { enableScripts: true },
  );
  panel.webview.html = getWebviewHtml();

  const send = (type: string, data: object = {}) =>
    panel.webview.postMessage({ type, ...data });

  try {
    let files: { rel: string; content: string }[] = [];

    if (isFolder) {
      send('status', { text: `Scanning ${path.basename(targetPath)}...` });
      files = collectFiles(targetPath);
    } else {
      send('status', { text: `Reading ${path.basename(targetPath)}...` });
      const content = fs.readFileSync(targetPath, 'utf8');
      files = [{ rel: path.basename(targetPath), content }];
    }

    if (files.length === 0) {
      send('error', { text: 'No supported source files found.' });
      return;
    }

    // Quick scan
    const issues = quickScan(files);
    send('quick', { issues });

    send('status', {
      text: `Analyzing ${files.length} file(s) with ${model}...`,
      color: '#f0a500',
    });

    const context = buildContext(files);
    const prompt  = `Files: ${files.map(f => f.rel).join(', ')}\n\n${context}`;
    const client  = new Anthropic({ apiKey });

    // Stream response
    const stream = await client.messages.stream({
      model,
      max_tokens: 4096,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
    });

    for await (const chunk of stream) {
      if (chunk.type === 'content_block_delta' && chunk.delta.type === 'text_delta') {
        send('chunk', { text: chunk.delta.text });
      }
    }

    send('done', { files: files.length });

  } catch (err: any) {
    send('error', { text: err.message || String(err) });
  }
}

// ── Activate ───────────────────────────────────────────────────────────────────
export function activate(ctx: vscode.ExtensionContext) {
  ctx.subscriptions.push(
    vscode.commands.registerCommand('vsec.reviewFile', async (uri?: vscode.Uri) => {
      const target = uri?.fsPath ?? vscode.window.activeTextEditor?.document.fileName;
      if (!target) {
        vscode.window.showErrorMessage('VSec: No file selected.');
        return;
      }
      await runReview(target, false, ctx);
    })
  );

  ctx.subscriptions.push(
    vscode.commands.registerCommand('vsec.reviewFolder', async (uri?: vscode.Uri) => {
      if (!uri?.fsPath) {
        vscode.window.showErrorMessage('VSec: No folder selected.');
        return;
      }
      await runReview(uri.fsPath, true, ctx);
    })
  );
}

export function deactivate() {}
