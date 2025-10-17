mouseconst fs = require('fs');
const path = require('path');
const http = require('http');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

async function main() {
  // Chalk v5 is ESM — import dynamically inside async context
  const chalk = (await import('chalk')).default;

  class ReactSecurityAnalyzer {
    constructor(chalkInstance) {
      this.vulnerabilities = [];
      this.fileCount = 0;
      this.startTime = Date.now();
      this.server = null;
      this.chalk = chalkInstance;
    }

    analyze(directory) {
      console.log(this.chalk.blue.bold('\n🔍 React Security Analyzer\n'));
      this.scanDirectory(directory);
      this.generateReport();
      this.startServer();
    }

    scanDirectory(dir) {
      const files = fs.readdirSync(dir);
      files.forEach(file => {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        if (stat.isDirectory()) {
          this.scanDirectory(filePath);
        } else if (this.isReactFile(file)) {
          this.fileCount++;
          this.analyzeFile(filePath);
        }
      });
    }

    isReactFile(filename) {
      return /\.(jsx?|tsx?)$/.test(filename);
    }

    analyzeFile(filePath) {
      try {
        const code = fs.readFileSync(filePath, 'utf-8');
        const ast = parser.parse(code, {
          sourceType: 'module',
          plugins: ['jsx', 'typescript', 'classProperties', 'decorators-legacy']
        });
        const relPath = path.relative(process.cwd(), filePath);

        traverse(ast, {
          JSXAttribute: (path) => this.checkDangerouslySetInnerHTML(path, relPath),
          CallExpression: (path) => {
            this.checkEval(path, relPath);
            this.checkDocumentWrite(path, relPath);
            this.checkWindowOpen(path, relPath);
          },
          JSXOpeningElement: (path) => {
            this.checkTargetBlank(path, relPath);
            this.checkIframeUsage(path, relPath);
          },
          MemberExpression: (path) => this.checkLocalStorageXSS(path, relPath),
          VariableDeclarator: (path) => this.checkUnsafeRefs(path, relPath),
          AssignmentExpression: (path) => this.checkStateInjection(path, relPath),
          JSXExpressionContainer: (path) => this.checkUnvalidatedProps(path, relPath),
          ImportDeclaration: (path) => this.checkInsecureDependencies(path, relPath),
        });
              } catch (error) {
        console.log(this.chalk.yellow(`⚠️  Could not parse ${filePath}: ${error.message}`));
      }
    }

    checkDangerouslySetInnerHTML(path, file) {
      if (path.node.name && path.node.name.name === 'dangerouslySetInnerHTML') {
        const line = path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A';
        const code = this.getCodeSnippet(path);
        const isSanitized = code.includes('DOMPurify') || code.includes('sanitize');

        this.addVulnerability({
          type: 'XSS',
          severity: isSanitized ? 'MEDIUM' : 'CRITICAL',
          title: 'Dangerous innerHTML Usage',
          description: isSanitized 
            ? 'Using dangerouslySetInnerHTML with sanitization, but requires careful review'
            : 'Using dangerouslySetInnerHTML without sanitization can lead to XSS attacks',
          file,
          line,
          code,
          recommendation: 'Use DOMPurify.sanitize() or avoid dangerouslySetInnerHTML entirely',
          cwe: 'CWE-79'
        });
      }
    }

    checkEval(path, file) {
      try {
        if (!path.node.callee) return;
        if (path.node.callee.name === 'eval' || 
            (path.node.callee.type === 'MemberExpression' && 
             path.node.callee.property && 
             path.node.callee.property.name === 'eval')) {
          this.addVulnerability({
            type: 'Code Injection',
            severity: 'CRITICAL',
            title: 'Eval Usage Detected',
            description: 'Using eval() can execute arbitrary code and lead to security vulnerabilities',
            file,
            line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
            code: this.getCodeSnippet(path),
            recommendation: 'Avoid eval(). Use JSON.parse() for JSON or Function constructor with strict validation',
            cwe: 'CWE-95'
          });
        }
      } catch (e) {
        // ignore
      }
    }

    checkDocumentWrite(path, file) {
      if (path.node.callee && 
          path.node.callee.type === 'MemberExpression' &&
          path.node.callee.object && 
          path.node.callee.object.name === 'document' &&
          path.node.callee.property && 
          (path.node.callee.property.name === 'write' || path.node.callee.property.name === 'writeln')) {
        this.addVulnerability({
          type: 'XSS',
          severity: 'HIGH',
          title: 'document.write() Usage',
          description: 'document.write() can be exploited for XSS attacks and breaks in modern React apps',
          file,
          line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
          code: this.getCodeSnippet(path),
          recommendation: 'Use React state and JSX for DOM manipulation',
          cwe: 'CWE-79'
        });
      }
    }

    checkWindowOpen(path, file) {
      if (path.node.callee && 
          path.node.callee.type === 'MemberExpression' &&
          path.node.callee.object && 
          path.node.callee.object.name === 'window' &&
          path.node.callee.property && 
          path.node.callee.property.name === 'open') {
        const args = path.node.arguments || [];
        const optsArg = args.length > 2 ? args[2] : null;
        let hasNoOpener = false;
        if (optsArg && optsArg.type === 'StringLiteral' && typeof optsArg.value === 'string') {
          const s = optsArg.value;
          hasNoOpener = s.includes('noopener') || s.includes('noreferrer');
        }

        this.addVulnerability({
          type: 'Tabnabbing',
          severity: hasNoOpener ? 'LOW' : 'MEDIUM',
          title: 'window.open() Without Proper Protection',
          description: 'window.open() without noopener can lead to tabnabbing attacks',
          file,
          line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
          code: this.getCodeSnippet(path),
          recommendation: 'Use window.open(url, "_blank", "noopener,noreferrer")',
          cwe: 'CWE-1022'
        });
      }
    }

    checkTargetBlank(path, file) {
      const attributes = path.node.attributes || [];
      const hasTargetBlank = attributes.some(attr => 
        attr.name && attr.name.name === 'target' && 
        attr.value && attr.value.value === '_blank'
      );

      if (hasTargetBlank) {
        const hasRel = attributes.some(attr => 
          attr.name && attr.name.name === 'rel' &&
          attr.value && typeof attr.value.value === 'string' &&
          (attr.value.value.includes('noopener') || attr.value.value.includes('noreferrer'))
        );

        if (!hasRel) {
          this.addVulnerability({
            type: 'Tabnabbing',
            severity: 'MEDIUM',
            title: 'Missing rel="noopener noreferrer"',
            description: 'Links with target="_blank" without rel="noopener noreferrer" are vulnerable to tabnabbing',
            file,
            line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
            code: this.getCodeSnippet(path),
            recommendation: 'Add rel="noopener noreferrer" to all target="_blank" links',
            cwe: 'CWE-1022'
          });
        }
      }
    }

    checkIframeUsage(path, file) {
      if (path.node.name && path.node.name.name === 'iframe') {
        const attributes = path.node.attributes || [];
        const hasSandbox = attributes.some(attr => attr.name && attr.name.name === 'sandbox');

        this.addVulnerability({
          type: 'Clickjacking',
          severity: hasSandbox ? 'LOW' : 'HIGH',
          title: 'Iframe Usage Detected',
          description: hasSandbox 
            ? 'Iframe has sandbox attribute, but verify restrictions are sufficient'
            : 'Iframe without sandbox attribute can be exploited for clickjacking attacks',
          file,
          line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
          code: this.getCodeSnippet(path),
          recommendation: 'Use sandbox attribute with minimal permissions or avoid iframes',
          cwe: 'CWE-1021'
        });
      }
    }

    checkLocalStorageXSS(path, file) {
      try {
        if (path.node.object && 
            (path.node.object.name === 'localStorage' || path.node.object.name === 'sessionStorage')) {
          const parent = path.findParent(p => p.isJSXExpressionContainer && p.isJSXExpressionContainer());
          if (parent) {
            this.addVulnerability({
              type: 'XSS',
              severity: 'HIGH',
              title: 'Unsafe Storage Data in JSX',
              description: 'Directly rendering localStorage/sessionStorage data can lead to stored XSS',
              file,
              line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
              code: this.getCodeSnippet(path),
              recommendation: 'Sanitize and validate all data from storage before rendering',
              cwe: 'CWE-79'
            });
          }
        }
      } catch (e) {
        // ignore
      }
    }

    checkUnsafeRefs(path, file) {
      try {
        if (path.node.init && path.node.init.callee) {
          const callee = path.node.init.callee;
          if (callee.name === 'useRef' || 
              (callee.type === 'MemberExpression' && callee.property && callee.property.name === 'createRef')) {
            const varName = path.node.id && path.node.id.name;
            const binding = varName ? path.scope.getBinding(varName) : null;
            if (binding) {
              binding.referencePaths.forEach(refPath => {
                const assignment = refPath.findParent(p => p.isAssignmentExpression && p.isAssignmentExpression());
                if (assignment && assignment.node.right && assignment.node.right.type === 'StringLiteral') {
                  this.addVulnerability({
                    type: 'XSS',
                    severity: 'MEDIUM',
                    title: 'Potential XSS via Ref Manipulation',
                    description: 'Directly setting innerHTML or other dangerous properties via refs',
                    file,
                    line: refPath.node.loc && refPath.node.loc.start ? refPath.node.loc.start.line : 'N/A',
                    code: this.getCodeSnippet(refPath),
                    recommendation: 'Use React state and JSX instead of direct DOM manipulation',
                    cwe: 'CWE-79'
                  });
                }
              });
            }
          }
        }
      } catch (e) {
        // ignore
      }
    }

    checkStateInjection(path, file) {
      try {
        if (path.node.left && 
            path.node.left.type === 'MemberExpression' &&
            path.node.left.property && 
            path.node.left.property.name === '__proto__') {
          this.addVulnerability({
            type: 'Prototype Pollution',
            severity: 'CRITICAL',
            title: 'Prototype Pollution Detected',
            description: 'Modifying __proto__ can lead to prototype pollution attacks',
            file,
            line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
            code: this.getCodeSnippet(path),
            recommendation: 'Never modify __proto__. Use Object.create(null) for safe objects',
            cwe: 'CWE-1321'
          });
        }
      } catch (e) {
        // ignore
      }
    }

    checkUnvalidatedProps(path, file) {
      try {
        if (!path.node.expression || path.node.expression.type !== 'MemberExpression') return;
        const obj = path.node.expression.object;
        const objName = obj && obj.name;
        const isProps = objName === 'props' || objName === 'this' || 
                       (obj.type === 'MemberExpression' && obj.property && obj.property.name === 'props');

        if (isProps) {
          const parent = path.parent;
          if (parent && parent.name && 
              (parent.name.name === 'dangerouslySetInnerHTML' || 
               parent.name.name === 'href' || 
               parent.name.name === 'src')) {
            this.addVulnerability({
              type: 'XSS',
              severity: 'HIGH',
              title: 'Unvalidated Props in Dangerous Context',
              description: 'Using unvalidated props in href, src, or innerHTML can lead to XSS',
              file,
              line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
              code: this.getCodeSnippet(path),
              recommendation: 'Validate and sanitize all props before using in dangerous contexts',
              cwe: 'CWE-79'
            });
          }
        }
      } catch (e) {
        // ignore
      }
    }

    checkInsecureDependencies(path, file) {
      try {
        const source = path.node.source && path.node.source.value;
        const vulnerablePackages = {
          'react-dom': { version: '<16.14.0', reason: 'Known XSS vulnerabilities' },
          'serialize-javascript': { version: '<3.1.0', reason: 'Code injection vulnerability' },
          'axios': { version: '<0.21.1', reason: 'SSRF vulnerability' }
        };

        Object.keys(vulnerablePackages).forEach(pkg => {
          if (source === pkg) {
            this.addVulnerability({
              type: 'Vulnerable Dependency',
              severity: 'HIGH',
              title: `Potentially Vulnerable Dependency: ${pkg}`,
              description: `${pkg} ${vulnerablePackages[pkg].reason}`,
              file,
              line: path.node.loc && path.node.loc.start ? path.node.loc.start.line : 'N/A',
              code: this.getCodeSnippet(path),
              recommendation: `Update ${pkg} to latest version and run npm audit`,
              cwe: 'CWE-1104'
            });
          }
        });
      } catch (e) {
        // ignore
      }
    }

    getCodeSnippet(path) {
      try {
        const node = path.node;
        if (node && node.loc && node.loc.start && node.loc.end) {
          const txt = path.toString();
          return txt.substring(0, 100) + (txt.length > 100 ? '...' : '');
        }
        return 'Code snippet unavailable';
      } catch (e) {
        return 'Code snippet unavailable';
      }
    }

    addVulnerability(vuln) {
      this.vulnerabilities.push({
        ...vuln,
        id: `VULN-${this.vulnerabilities.length + 1}`,
        timestamp: new Date().toISOString()
      });
    }

    generateReport() {
      const endTime = Date.now();
      const duration = ((endTime - this.startTime) / 1000).toFixed(2);

      const summary = {
        totalFiles: this.fileCount,
        totalVulnerabilities: this.vulnerabilities.length,
        critical: this.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        high: this.vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: this.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: this.vulnerabilities.filter(v => v.severity === 'LOW').length,
        scanDuration: duration,
        timestamp: new Date().toISOString()
      };

      this.summary = summary;

      // Console output
      console.log(this.chalk.green(`\n✅ Scan completed in ${duration}s`));
      console.log(this.chalk.blue(`📁 Files scanned: ${summary.totalFiles}`));
      console.log(this.chalk.yellow(`🔍 Vulnerabilities found: ${summary.totalVulnerabilities}\n`));

      if (summary.critical > 0) console.log(this.chalk.red.bold(`   🔴 Critical: ${summary.critical}`));
      if (summary.high > 0) console.log(this.chalk.red(`   🟠 High: ${summary.high}`));
      if (summary.medium > 0) console.log(this.chalk.yellow(`   🟡 Medium: ${summary.medium}`));
      if (summary.low > 0) console.log(this.chalk.blue(`   🔵 Low: ${summary.low}`));

      // Still save JSON report
      const jsonReport = JSON.stringify({
        summary,
        vulnerabilities: this.vulnerabilities
      }, null, 2);
      fs.writeFileSync('report.json', jsonReport);
      console.log(this.chalk.green('\n📊 Report generated:'));
      console.log(this.chalk.blue('   - report.json (Machine-readable report)'));
    }

    startServer() {
      const PORT = process.env.PORT || 3000;

      this.server = http.createServer((req, res) => {
        // Set CORS headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

        if (req.url === '/' || req.url === '/index.html') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(this.generateHTMLReport(this.summary));
        } else if (req.url === '/api/vulnerabilities') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            summary: this.summary,
            vulnerabilities: this.vulnerabilities
          }));
        } else if (req.url === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 Not Found');
        }
      });

      this.server.listen(PORT, () => {
        console.log(this.chalk.green.bold(`\n🌐 Server started successfully!`));
        console.log(this.chalk.cyan(`\n   📊 View Report: http://localhost:${PORT}`));
        console.log(this.chalk.cyan(`   🔌 API Endpoint: http://localhost:${PORT}/api/vulnerabilities`));
        console.log(this.chalk.yellow(`\n   Press Ctrl+C to stop the server\n`));
      });

      // Handle graceful shutdown
      process.on('SIGINT', () => {
        console.log(this.chalk.yellow('\n\n🛑 Shutting down server...'));
        this.server.close(() => {
          console.log(this.chalk.green('✅ Server closed successfully\n'));
          process.exit(0);
        });
      });

      process.on('SIGTERM', () => {
        console.log(this.chalk.yellow('\n\n🛑 Shutting down server...'));
        this.server.close(() => {
          console.log(this.chalk.green('✅ Server closed successfully\n'));
          process.exit(0);
        });
      });
    }

    generateHTMLReport(summary) {
      const vulnsByType = this.groupBy(this.vulnerabilities, 'type');
      const vulnsBySeverity = this.groupBy(this.vulnerabilities, 'severity');
      const vulnsByFile = this.groupBy(this.vulnerabilities, 'file');

      return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>React Security Analysis Report</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    :root {
      --primary: #6366f1;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #fbbf24;
      --low: #3b82f6;
      --bg: #0f172a;
      --bg-secondary: #1e293b;
      --bg-tertiary: #334155;
      --text: #e2e8f0;
      --text-secondary: #94a3b8;
      --border: #334155;
      --success: #10b981;
    }

    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }

    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem;
    }

    header {
      background: linear-gradient(135deg, var(--primary), #8b5cf6);
      padding: 3rem 2rem;
      border-radius: 1rem;
      margin-bottom: 2rem;
      box-shadow: 0 20px 60px rgba(99, 102, 241, 0.3);
    }

    h1 {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .subtitle {
      color: rgba(255, 255, 255, 0.9);
      font-size: 1.1rem;
    }

    .live-indicator {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(16, 185, 129, 0.2);
      color: var(--success);
      padding: 0.5rem 1rem;
      border-radius: 2rem;
      font-size: 0.9rem;
      margin-top: 1rem;
      border: 1px solid var(--success);
    }

    .live-dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
      animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background: var(--bg-secondary);
      padding: 1.5rem;
      border-radius: 0.75rem;
      border: 1px solid var(--border);
      transition: transform 0.2s, box-shadow 0.2s;
    }

    .stat-card:hover {
      transform: translateY(-4px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }

    .stat-value {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }

    .stat-label {
      color: var(--text-secondary);
      font-size: 0.95rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .severity-badges {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      margin-top: 1rem;
    }

    .badge {
      padding: 0.5rem 1rem;
      border-radius: 0.5rem;
      font-weight: 600;
      font-size: 0.9rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .badge-critical {
      background: rgba(239, 68, 68, 0.2);
      color: var(--critical);
      border: 1px solid var(--critical);
    }

    .badge-high {
      background: rgba(249, 115, 22, 0.2);
      color: var(--high);
      border: 1px solid var(--high);
    }

    .badge-medium {
      background: rgba(251, 191, 36, 0.2);
      color: var(--medium);
      border: 1px solid var(--medium);
    }

    .badge-low {
      background: rgba(59, 130, 246, 0.2);
      color: var(--low);
      border: 1px solid var(--low);
    }

    .tabs {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 2rem;
      background: var(--bg-secondary);
      padding: 0.5rem;
      border-radius: 0.75rem;
      overflow-x: auto;
    }

    .tab {
      padding: 0.75rem 1.5rem;
      background: transparent;
      border: none;
      color: var(--text-secondary);
      cursor: pointer;
      border-radius: 0.5rem;
      font-size: 1rem;
      font-weight: 500;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .tab:hover {
      background: var(--bg-tertiary);
      color: var(--text);
    }

    .tab.active {
      background: var(--primary);
      color: white;
    }

    .tab-content {
      display: none;
    }

    .tab-content.active {
      display: block;
      animation: fadeIn 0.3s;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .vuln-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-left: 4px solid;
      border-radius: 0.75rem;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      transition: transform 0.2s, box-shadow 0.2s;
    }

    .vuln-card:hover {
      transform: translateX(4px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }

    .vuln-card.critical {
      border-left-color: var(--critical);
    }

    .vuln-card.high {
      border-left-color: var(--high);
    }

    .vuln-card.medium {
      border-left-color: var(--medium);
    }

    .vuln-card.low {
      border-left-color: var(--low);
    }

    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: start;
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .vuln-title {
      font-size: 1.25rem;
      font-weight: 600;
      color: var(--text);
    }

    .vuln-meta {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      margin: 1rem 0;
      font-size: 0.9rem;
    }

    .meta-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--text-secondary);
    }

    .vuln-description {
      color: var(--text-secondary);
      margin-bottom: 1rem;
      line-height: 1.6;
    }

    .code-block {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1rem;
      margin: 1rem 0;
      overflow-x: auto;
      font-family: 'Courier New', monospace;
      font-size: 0.9rem;
    }

    .recommendation {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid var(--success);
      border-radius: 0.5rem;
      padding: 1rem;
      margin-top: 1rem;
    }

    .recommendation-title {
      color: var(--success);
      font-weight: 600;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .chart-container {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 2rem;
      margin-bottom: 2rem;
    }

    .file-list {
      list-style: none;
    }

    .file-item {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1rem;
      margin-bottom: 1rem;
    }

    .file-name {
      font-weight: 600;
      color: var(--primary);
      margin-bottom: 0.5rem;
    }

    .filter-bar {
      display: flex;
      gap: 1rem;
      margin-bottom: 2rem;
      flex-wrap: wrap;
    }

    .filter-btn {
      padding: 0.5rem 1rem;
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      color: var(--text);
      cursor: pointer;
      transition: all 0.2s;
    }

    .filter-btn:hover {
      background: var(--bg-tertiary);
    }

    .filter-btn.active {
      background: var(--primary);
      border-color: var(--primary);
    }

    footer {
      text-align: center;
      margin-top: 3rem;
      padding: 2rem;
      color: var(--text-secondary);
      border-top: 1px solid var(--border);
    }

    @media (max-width: 768px) {
      .container {
        padding: 1rem;
      }

      h1 {
        font-size: 1.75rem;
      }

      .stats-grid {
        grid-template-columns: 1fr;
      }

      .tabs {
        flex-direction: column;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>
        <span>🛡️</span>
        React Security Analysis Report
      </h1>
      <p class="subtitle">Comprehensive security scan results for your React application</p>
      <div class="live-indicator">
        <span class="live-dot"></span>
        Live Server Report
      </div>
      <div class="severity-badges">
        <span class="badge badge-critical">🔴 ${summary.critical} Critical</span>
        <span class="badge badge-high">🟠 ${summary.high} High</span>
        <span class="badge badge-medium">🟡 ${summary.medium} Medium</span>
        <span class="badge badge-low">🔵 ${summary.low} Low</span>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">${summary.totalFiles}</div>
        <div class="stat-label">Files Scanned</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${summary.totalVulnerabilities}</div>
        <div class="stat-label">Vulnerabilities Found</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${summary.scanDuration}s</div>
        <div class="stat-label">Scan Duration</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${new Date(summary.timestamp).toLocaleTimeString()}</div>
        <div class="stat-label">Scan Time</div>
      </div>
    </div>

    <div class="tabs">
      <button class="tab active" onclick="showTab('all')">All Vulnerabilities</button>
      <button class="tab" onclick="showTab('severity')">By Severity</button>
      <button class="tab" onclick="showTab('type')">By Type</button>
      <button class="tab" onclick="showTab('files')">By File</button>
      <button class="tab" onclick="showTab('charts')">Analytics</button>
    </div>

    <div id="all" class="tab-content active">
      <div class="filter-bar">
        <button class="filter-btn active" onclick="filterVulns('ALL')">All</button>
        <button class="filter-btn" onclick="filterVulns('CRITICAL')">Critical</button>
        <button class="filter-btn" onclick="filterVulns('HIGH')">High</button>
        <button class="filter-btn" onclick="filterVulns('MEDIUM')">Medium</button>
        <button class="filter-btn" onclick="filterVulns('LOW')">Low</button>
      </div>
      <div id="vuln-list">
        ${this.vulnerabilities.map(v => this.renderVulnerability(v)).join('')}
      </div>
    </div>

    <div id="severity" class="tab-content">
      ${Object.entries(vulnsBySeverity).map(([severity, vulns]) => `
        <h2 style="color: var(--${severity.toLowerCase()}); margin: 2rem 0 1rem;">${severity} (${vulns.length})</h2>
        ${vulns.map(v => this.renderVulnerability(v)).join('')}
      `).join('')}
    </div>

    <div id="type" class="tab-content">
      ${Object.entries(vulnsByType).map(([type, vulns]) => `
        <h2 style="margin: 2rem 0 1rem; color: var(--primary);">${type} (${vulns.length})</h2>
        ${vulns.map(v => this.renderVulnerability(v)).join('')}
      `).join('')}
    </div>

    <div id="files" class="tab-content">
      <ul class="file-list">
        ${Object.entries(vulnsByFile).map(([file, vulns]) => `
          <li class="file-item">
            <div class="file-name">📄 ${file}</div>
            <div style="color: var(--text-secondary); margin-top: 0.5rem;">
              ${vulns.length} vulnerabilities found
            </div>
            <div class="severity-badges" style="margin-top: 1rem;">
              ${this.renderFileSeverities(vulns)}
            </div>
          </li>
        `).join('')}
      </ul>
    </div>

    <div id="charts" class="tab-content">
      <div class="chart-container">
        <h2 style="margin-bottom: 1.5rem;">Vulnerability Distribution</h2>
        <canvas id="severityChart" style="max-height: 300px;"></canvas>
      </div>
      <div class="chart-container">
        <h2 style="margin-bottom: 1.5rem;">Vulnerabilities by Type</h2>
        <canvas id="typeChart" style="max-height: 300px;"></canvas>
      </div>
    </div>

    <footer>
      <p>Report generated on ${new Date(summary.timestamp).toLocaleString()}</p>
      <p style="margin-top: 0.5rem;">React Security Analyzer v1.0 - Built with AST Analysis</p>
      <p style="margin-top: 0.5rem; color: var(--success);">🌐 Hosted on http://localhost:${process.env.PORT || 3000}</p>
    </footer>
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
  <script>
    const vulnerabilities = ${JSON.stringify(this.vulnerabilities)};

    function showTab(tabName) {
      document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
      
      event.target.classList.add('active');
      document.getElementById(tabName).classList.add('active');

      if (tabName === 'charts') {
        setTimeout(initCharts, 100);
      }
    }

    function filterVulns(severity) {
      document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');

      const cards = document.querySelectorAll('#vuln-list .vuln-card');
      cards.forEach(card => {
        if (severity === 'ALL' || card.classList.contains(severity.toLowerCase())) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }

    function initCharts() {
      const severityCtx = document.getElementById('severityChart');
      const typeCtx = document.getElementById('typeChart');

      if (window.severityChart) window.severityChart.destroy();
      if (window.typeChart) window.typeChart.destroy();

      const severityData = {
        critical: ${summary.critical},
        high: ${summary.high},
        medium: ${summary.medium},
        low: ${summary.low}
      };

      window.severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{
            data: [severityData.critical, severityData.high, severityData.medium, severityData.low],
            backgroundColor: ['#ef4444', '#f97316', '#fbbf24', '#3b82f6'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#e2e8f0',
                font: { size: 14 }
              }
            }
          }
        }
      });

      const typeData = {};
      vulnerabilities.forEach(v => {
        typeData[v.type] = (typeData[v.type] || 0) + 1;
      });

      window.typeChart = new Chart(typeCtx, {
        type: 'bar',
        data: {
          labels: Object.keys(typeData),
          datasets: [{
            label: 'Count',
            data: Object.values(typeData),
            backgroundColor: '#6366f1',
            borderRadius: 8
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: { display: false }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: { color: '#94a3b8' },
              grid: { color: '#334155' }
            },
            x: {
              ticks: { color: '#94a3b8' },
              grid: { display: false }
            }
          }
        }
      });
    }

    document.addEventListener('DOMContentLoaded', () => {
      console.log('React Security Report loaded with', vulnerabilities.length, 'vulnerabilities');
    });
  </script>
</body>
</html>`;
    }

    renderVulnerability(v) {
      return `
        <div class="vuln-card ${v.severity.toLowerCase()}">
          <div class="vuln-header">
            <div>
              <div class="vuln-title">${v.title}</div>
              <div class="vuln-meta">
                <span class="meta-item">
                  <span class="badge badge-${v.severity.toLowerCase()}">${v.severity}</span>
                </span>
                <span class="meta-item">
                  <span>📦</span> ${v.type || ''}
                </span>
                <span class="meta-item">
                  <span>🔖</span> ${v.cwe || ''}
                </span>
                <span class="meta-item">
                  <span>🆔</span> ${v.id}
                </span>
              </div>
            </div>
          </div>
          <div class="vuln-description">${v.description}</div>
          <div class="vuln-meta">
            <span class="meta-item">
              <span>📄</span> ${v.file}
            </span>
            <span class="meta-item">
              <span>📍</span> Line ${v.line}
            </span>
          </div>
          ${v.code ? `
            <div class="code-block">
              <code>${this.escapeHtml(v.code)}</code>
            </div>
          ` : ''}
          <div class="recommendation">
            <div class="recommendation-title">
              <span>💡</span>
              Recommendation
            </div>
            <div>${v.recommendation}</div>
          </div>
        </div>
      `;
    }

    renderFileSeverities(vulns) {
      const counts = {
        CRITICAL: vulns.filter(v => v.severity === 'CRITICAL').length,
        HIGH: vulns.filter(v => v.severity === 'HIGH').length,
        MEDIUM: vulns.filter(v => v.severity === 'MEDIUM').length,
        LOW: vulns.filter(v => v.severity === 'LOW').length
      };

      return Object.entries(counts)
        .filter(([_, count]) => count > 0)
        .map(([severity, count]) => 
          `<span class="badge badge-${severity.toLowerCase()}">${count} ${severity}</span>`
        )
        .join('');
    }

    escapeHtml(text) {
      if (!text || typeof text !== 'string') return '';
      const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
      };
      return text.replace(/[&<>"']/g, m => map[m]);
    }

    groupBy(array, key) {
      return array.reduce((result, item) => {
        (result[item[key]] = result[item[key]] || []).push(item);
        return result;
      }, {});
    }
  }

  // Main execution
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log(chalk.red('❌ Please provide a directory to scan'));
    console.log(chalk.blue('Usage: node react-security-analyzer.js <directory>'));
    process.exit(1);
  }

  const analyzer = new ReactSecurityAnalyzer(chalk);
  analyzer.analyze(args[0]);
}

// Run async main
main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
