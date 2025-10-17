/**
 * Security Rules Configuration for React Security Analyzer
 * Defines all security rules, patterns, and detection logic
 */

module.exports = {
  // XSS Vulnerabilities
  xssRules: {
    dangerouslySetInnerHTML: {
      severity: 'CRITICAL',
      cwe: 'CWE-79',
      description: 'Direct HTML injection can lead to XSS attacks',
      patterns: ['dangerouslySetInnerHTML'],
      recommendation: 'Use DOMPurify.sanitize() or avoid dangerouslySetInnerHTML',
      examples: {
        vulnerable: '<div dangerouslySetInnerHTML={{__html: userInput}} />',
        secure: '<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />'
      }
    },
    documentWrite: {
      severity: 'HIGH',
      cwe: 'CWE-79',
      description: 'document.write() can be exploited for XSS',
      patterns: ['document.write', 'document.writeln'],
      recommendation: 'Use React state and JSX instead',
      examples: {
        vulnerable: 'document.write(userInput)',
        secure: 'setState({content: sanitizedInput})'
      }
    },
    unsanitizedProps: {
      severity: 'HIGH',
      cwe: 'CWE-79',
      description: 'Rendering unsanitized user input',
      patterns: ['props', 'state'],
      dangerousAttributes: ['href', 'src', 'dangerouslySetInnerHTML', 'style'],
      recommendation: 'Validate and sanitize all user input'
    },
    localStorageXSS: {
      severity: 'HIGH',
      cwe: 'CWE-79',
      description: 'Rendering data from localStorage without sanitization',
      patterns: ['localStorage', 'sessionStorage'],
      recommendation: 'Sanitize data from storage before rendering'
    }
  },

  // Code Injection
  codeInjectionRules: {
    eval: {
      severity: 'CRITICAL',
      cwe: 'CWE-95',
      description: 'eval() executes arbitrary code',
      patterns: ['eval(', 'window.eval', 'global.eval'],
      recommendation: 'Use JSON.parse() or safer alternatives',
      examples: {
        vulnerable: 'eval(userInput)',
        secure: 'JSON.parse(validatedJSON)'
      }
    },
    functionConstructor: {
      severity: 'CRITICAL',
      cwe: 'CWE-95',
      description: 'Function constructor can execute arbitrary code',
      patterns: ['new Function(', 'Function('],
      recommendation: 'Avoid dynamic code execution'
    },
    setTimeout: {
      severity: 'MEDIUM',
      cwe: 'CWE-95',
      description: 'setTimeout with string argument can execute arbitrary code',
      patterns: ['setTimeout', 'setInterval'],
      recommendation: 'Use function callbacks instead of strings'
    }
  },

  // Prototype Pollution
  prototypePollutionRules: {
    protoAccess: {
      severity: 'CRITICAL',
      cwe: 'CWE-1321',
      description: '__proto__ manipulation can pollute prototypes',
      patterns: ['__proto__', 'constructor.prototype', 'Object.prototype'],
      recommendation: 'Use Object.create(null) for safe objects',
      examples: {
        vulnerable: 'obj.__proto__.isAdmin = true',
        secure: 'const safeObj = Object.create(null)'
      }
    },
    unsafeMerge: {
      severity: 'HIGH',
      cwe: 'CWE-1321',
      description: 'Unsafe object merging can lead to prototype pollution',
      patterns: ['Object.assign', 'spread operator', 'merge'],
      recommendation: 'Validate keys before merging objects'
    }
  },

  // Tabnabbing
  tabnabbingRules: {
    targetBlank: {
      severity: 'MEDIUM',
      cwe: 'CWE-1022',
      description: 'target="_blank" without rel="noopener" vulnerable to tabnabbing',
      patterns: ['target="_blank"'],
      requiredAttributes: ['rel="noopener noreferrer"'],
      recommendation: 'Always add rel="noopener noreferrer" to external links',
      examples: {
        vulnerable: '<a href="..." target="_blank">Link</a>',
        secure: '<a href="..." target="_blank" rel="noopener noreferrer">Link</a>'
      }
    },
    windowOpen: {
      severity: 'MEDIUM',
      cwe: 'CWE-1022',
      description: 'window.open() without noopener',
      patterns: ['window.open'],
      recommendation: 'Use window.open(url, "_blank", "noopener,noreferrer")'
    }
  },

  // Clickjacking
  clickjackingRules: {
    unsafeIframe: {
      severity: 'HIGH',
      cwe: 'CWE-1021',
      description: 'iframe without sandbox attribute',
      patterns: ['<iframe'],
      requiredAttributes: ['sandbox'],
      recommendation: 'Use sandbox attribute with minimal permissions',
      examples: {
        vulnerable: '<iframe src="..." />',
        secure: '<iframe src="..." sandbox="allow-scripts" />'
      }
    }
  },

  // Insecure Direct Object References
  idorRules: {
    unsafeURLParams: {
      severity: 'HIGH',
      cwe: 'CWE-639',
      description: 'Direct use of URL parameters without validation',
      patterns: ['useParams', 'useSearchParams', 'location.search'],
      recommendation: 'Validate and authorize all parameters'
    }
  },

  // Authentication & Authorization
  authRules: {
    clientSideAuth: {
      severity: 'CRITICAL',
      cwe: 'CWE-602',
      description: 'Client-side only authentication',
      patterns: ['localStorage.getItem(\'token\')', 'sessionStorage.getItem(\'token\')'],
      recommendation: 'Always validate authentication on the server'
    },
    hardcodedSecrets: {
      severity: 'CRITICAL',
      cwe: 'CWE-798',
      description: 'Hardcoded secrets or API keys',
      patterns: [
        'api_key',
        'apiKey',
        'secret',
        'password',
        'token',
        'private_key'
      ],
      recommendation: 'Use environment variables for secrets'
    }
  },

  // Vulnerable Dependencies
  dependencyRules: {
    knownVulnerable: {
      'react': {
        vulnerable: ['<16.14.0'],
        severity: 'HIGH',
        cwe: 'CWE-1104',
        reason: 'Known XSS vulnerabilities',
        recommendation: 'Update to React 16.14.0 or higher'
      },
      'react-dom': {
        vulnerable: ['<16.14.0'],
        severity: 'HIGH',
        cwe: 'CWE-1104',
        reason: 'Known XSS vulnerabilities',
        recommendation: 'Update to React DOM 16.14.0 or higher'
      },
      'serialize-javascript': {
        vulnerable: ['<3.1.0'],
        severity: 'CRITICAL',
        cwe: 'CWE-502',
        reason: 'Code injection vulnerability',
        recommendation: 'Update to 3.1.0 or higher'
      },
      'axios': {
        vulnerable: ['<0.21.1'],
        severity: 'HIGH',
        cwe: 'CWE-918',
        reason: 'SSRF vulnerability',
        recommendation: 'Update to 0.21.1 or higher'
      },
      'lodash': {
        vulnerable: ['<4.17.21'],
        severity: 'HIGH',
        cwe: 'CWE-1321',
        reason: 'Prototype pollution',
        recommendation: 'Update to 4.17.21 or higher'
      }
    }
  },

  // Sensitive Data Exposure
  dataExposureRules: {
    consoleLog: {
      severity: 'LOW',
      cwe: 'CWE-532',
      description: 'console.log() may expose sensitive data',
      patterns: ['console.log', 'console.dir', 'console.table'],
      recommendation: 'Remove console statements in production'
    },
    errorMessages: {
      severity: 'MEDIUM',
      cwe: 'CWE-209',
      description: 'Detailed error messages may expose system information',
      patterns: ['error.stack', 'error.message'],
      recommendation: 'Use generic error messages in production'
    }
  },

  // React-Specific Patterns
  reactPatterns: {
    unsafeRefs: {
      severity: 'MEDIUM',
      cwe: 'CWE-79',
      description: 'Direct DOM manipulation via refs',
      patterns: ['.current.innerHTML', '.current.outerHTML'],
      recommendation: 'Use React state and JSX'
    },
    unsafeLifecycle: {
      severity: 'LOW',
      cwe: 'CWE-362',
      description: 'Unsafe lifecycle method usage',
      patterns: ['componentWillMount', 'componentWillReceiveProps', 'componentWillUpdate'],
      recommendation: 'Use safe alternatives like getDerivedStateFromProps'
    },
    keyProp: {
      severity: 'LOW',
      cwe: 'CWE-1240',
      description: 'Missing or improper key prop in lists',
      patterns: ['.map(', 'Array.map'],
      recommendation: 'Use stable, unique keys for list items'
    }
  },

  // Regular Expressions for Detection
  regexPatterns: {
    // API Keys
    awsAccessKey: /AKIA[0-9A-Z]{16}/,
    awsSecretKey: /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/, 
    githubToken: /ghp_[0-9a-zA-Z]{36}/,
    googleApiKey: /AIza[0-9A-Za-z\-_]{35}/,
    
    // Sensitive patterns
    privateKey: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    password: /(password|passwd|pwd)[\s]*[=:]['"]([^'"]+)['"]/i,
    
    // SQL Injection patterns
    sqlQuery: /(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.*FROM|INTO|TABLE/i,
    
    // URL patterns
    dataUrl: /data:[^,]*base64/,
    javascriptUrl: /javascript:/i
  },

  // Severity Levels
  severityLevels: {
    CRITICAL: {
      score: 10,
      color: '#ef4444',
      description: 'Requires immediate attention'
    },
    HIGH: {
      score: 7,
      color: '#f97316',
      description: 'Should be fixed soon'
    },
    MEDIUM: {
      score: 4,
      color: '#fbbf24',
      description: 'Should be reviewed'
    },
    LOW: {
      score: 2,
      color: '#3b82f6',
      description: 'Minor issue'
    }
  },

  // CWE Categories
  cweCategories: {
    'CWE-79': 'Cross-site Scripting (XSS)',
    'CWE-95': 'Improper Neutralization of Directives in Dynamically Evaluated Code',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-639': 'Insecure Direct Object References',
    'CWE-798': 'Use of Hard-coded Credentials',
    'CWE-918': 'Server-Side Request Forgery (SSRF)',
    'CWE-1021': 'Improper Restriction of Rendered UI Layers',
    'CWE-1022': 'Use of Web Link to Untrusted Target with window.opener Access',
    'CWE-1104': 'Use of Unmaintained Third Party Components',
    'CWE-1321': 'Improperly Controlled Modification of Object Prototype Attributes',
    'CWE-532': 'Insertion of Sensitive Information into Log File',
    'CWE-209': 'Generation of Error Message Containing Sensitive Information',
    'CWE-362': 'Race Condition',
    'CWE-1240': 'Use of a Cryptographic Primitive with a Risky Implementation'
  }
};
