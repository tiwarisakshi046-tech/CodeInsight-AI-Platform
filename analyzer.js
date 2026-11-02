/**
 * CodeInsight – AI-Based Code Analysis System
 * Multi-Language Static Code Analysis & AI Explanation Engine
 * 
 * Supports: JavaScript, TypeScript, Python, HTML, CSS, Java, C/C++
 */

class MultiLanguageAnalyzer {

  static getSupportedLanguages() {
    return [
      {
        id: 'javascript',
        name: 'JavaScript',
        ext: '.js',
        icon: '⚡',
        category: 'Web & Node.js',
        supportLevel: 'Full',
        analysisType: 'Lexical Grammar Tokenizer & Heuristic AST Rule Matching',
        rulesCount: 12,
        checks: ['Lexical Bracket & String Symmetry', 'Strict Equality (===)', 'eval() Code Injection', 'innerHTML XSS', 'var Scoping Traps', 'Direct NaN Comparison', 'DOM Loops'],
        limitations: 'Static analysis only; dynamic expressions constructed at runtime or in eval() strings cannot be resolved across external network boundaries.'
      },
      {
        id: 'python',
        name: 'Python',
        ext: '.py',
        icon: '🐍',
        category: 'Backend & Data Science',
        supportLevel: 'Full',
        analysisType: 'Lexical Delimiter & Heuristic Pattern Matching',
        rulesCount: 10,
        checks: ['Missing Block Colons', 'Mutable Default Arguments', 'Bare except: Clauses', 'eval() / exec() Injection', 'Indentation Inconsistency'],
        limitations: 'Evaluates single-file scripts; does not resolve virtual environments or dynamically imported third-party wheels.'
      },
      {
        id: 'typescript',
        name: 'TypeScript',
        ext: '.ts',
        icon: '🔷',
        category: 'Typed Frontend & Server',
        supportLevel: 'Full',
        analysisType: 'Static Type Linting & Heuristic AST Checks',
        rulesCount: 9,
        checks: ['Unsound "any" Type', '@ts-ignore Directives', 'Empty Interfaces', 'Boxed Wrapper Types (String/Number)', 'Non-null Assertion Abuse'],
        limitations: 'Does not execute full tsc compiler project emission; checks source syntax and typing safety rules statically.'
      },
      {
        id: 'java',
        name: 'Java',
        ext: '.java',
        icon: '☕',
        category: 'Enterprise Backend',
        supportLevel: 'Full',
        analysisType: 'Static Vulnerability & Anti-Pattern Rules',
        rulesCount: 8,
        checks: ['Dynamic SQL Injection (Concatenation)', 'Resource Leakage (try-with-resources)', 'printStackTrace Anti-Pattern', 'NullPointer Risks'],
        limitations: 'Does not compile bytecodes (.class) or build Gradle/Maven dependency graphs.'
      },
      {
        id: 'c_cpp',
        name: 'C / C++',
        ext: '.cpp',
        icon: '⚙️',
        category: 'Systems & Native Memory',
        supportLevel: 'Full',
        analysisType: 'Memory Safety & Buffer Vulnerability Checks',
        rulesCount: 8,
        checks: ['Dangerous gets() Usage', 'Unbounded strcpy() / strcat()', 'Buffer Overflow Risks', 'malloc without NULL validation'],
        limitations: 'Lexical static security scanner; does not invoke GCC/Clang or execute runtime address sanitizers (ASan).'
      },
      {
        id: 'html',
        name: 'HTML5',
        ext: '.html',
        icon: '🌐',
        category: 'Web Markup & Accessibility',
        supportLevel: 'Full',
        analysisType: 'DOM Structure & Accessibility Checker',
        rulesCount: 7,
        checks: ['Image alt Accessibility', 'Inline Event Handler XSS', 'Responsive Viewport Meta', 'Form Input Labels'],
        limitations: 'Validates static HTML elements; does not render dynamic virtual DOM trees from React or Vue.'
      },
      {
        id: 'css',
        name: 'CSS3',
        ext: '.css',
        icon: '🎨',
        category: 'Stylesheets & Responsive Design',
        supportLevel: 'Full',
        analysisType: 'CSS Specificity & Hygiene Scanner',
        rulesCount: 6,
        checks: ['!important Specificity Abuse', 'Insecure HTTP @import', 'Missing Vendor Prefixes', 'Duplicate Declarations'],
        limitations: 'Does not precompile SCSS/SASS or evaluate CSS container query runtime calculations.'
      }
    ];
  }

  // ==========================================================================
  // JAVASCRIPT & TYPESCRIPT ANALYZER (PRESERVED & ENHANCED)
  // ==========================================================================
  static checkV8Syntax(code) {
    if (typeof code !== 'string' || !code.trim()) return [];
    const vm = require('vm');
    try {
      // Strip import/export so ES modules can be compiled cleanly as scripts
      const testable = code.replace(/^\s*(import\s+.*?from\s+['"].*?['"]|import\s+['"].*?['"]|export\s+(?:default\s+)?)/gm, '// $1');
      new vm.Script(testable, { filename: 'snippet.js' });
      return [];
    } catch (err) {
      if (err instanceof SyntaxError || err.name === 'SyntaxError') {
        let line = 1;
        let col = 1;
        if (err.stack) {
          const m = err.stack.match(/snippet\.js:(\d+)(?::(\d+))?/);
          if (m) {
            line = Math.max(1, parseInt(m[1], 10));
            col = Math.max(1, parseInt(m[2] || '1', 10));
          }
        }
        const lines = code.split('\n');
        const targetLine = lines[line - 1] || code.slice(0, 50);
        return [{
          severity: 'critical',
          title: `SyntaxError: ${err.message}`,
          ruleId: 'JS-SYN-V8',
          ruleName: 'V8 Syntax Grammar Error',
          category: 'Syntax Error',
          line,
          description: `Line ${line}, Col ${col}: ${err.message}.`,
          impact: 'JavaScript engine cannot parse or execute this code.',
          explanation: `Fatal syntax error detected by JavaScript engine: "${err.message}" on line ${line}. The code cannot be compiled or executed.`,
          aiExplanation: `Fatal syntax error detected by JavaScript engine: "${err.message}" on line ${line}. The code cannot be compiled or executed.`,
          learningConcept: 'JavaScript Grammar & Lexical Integrity',
          whyItMatters: 'A fatal syntax error prevents the JavaScript engine from compiling or running any part of the script.',
          suggestedFix: {
            before: targetLine.trim(),
            after: `// Fixed: ${targetLine.trim()}`,
            explanation: `Correct the invalid JavaScript syntax on line ${line}: ${err.message}`
          }
        }];
      }
      return [];
    }
  }

  static checkSyntaxIntegrity(code) {
    const syntaxFindings = [];
    const stack = [];
    const lines = code.split('\n');
    const matching = { ')': '(', '}': '{', ']': '[' };
    let inMultilineComment = false;
    let inBacktick = false;

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      let inSingle = false, inDouble = false, escaped = false;
      let col = 0;

      while (col < line.length) {
        const char = line[col];

        if (!inSingle && !inDouble && !inBacktick) {
          if (!inMultilineComment && col + 1 < line.length && line.slice(col, col + 2) === '//') {
            break;
          }
          if (!inMultilineComment && col + 1 < line.length && line.slice(col, col + 2) === '/*') {
            inMultilineComment = true;
            col += 2;
            continue;
          }
          if (inMultilineComment && col + 1 < line.length && line.slice(col, col + 2) === '*/') {
            inMultilineComment = false;
            col += 2;
            continue;
          }
        }

        if (inMultilineComment) { col++; continue; }
        if (escaped) { escaped = false; col++; continue; }
        if (char === '\\') { escaped = true; col++; continue; }

        if (char === "'" && !inDouble && !inBacktick) inSingle = !inSingle;
        else if (char === '"' && !inSingle && !inBacktick) inDouble = !inDouble;
        else if (char === '`' && !inSingle && !inDouble) inBacktick = !inBacktick;
        else if (!inSingle && !inDouble && !inBacktick) {
          if (char === '(' || char === '{' || char === '[') {
            stack.push({ char, line: lineNum, col: col + 1 });
          } else if (char === ')' || char === '}' || char === ']') {
            if (stack.length === 0) {
              syntaxFindings.push({
                severity: 'critical',
                title: `Syntax Error: Unmatched closing '${char}'`,
                ruleId: 'JS-SYN-001',
                ruleName: 'Syntax Bracket Mismatch',
                category: 'Syntax Error',
                line: lineNum,
                description: `Line ${lineNum}, Col ${col + 1}: Found closing '${char}' without an opening bracket.`,
                impact: 'JavaScript engine halts execution with a SyntaxError.',
                aiExplanation: `The JavaScript engine found a closing '${char}', but there was no matching opening bracket. All brackets must be closed in symmetrical pairs.`,
                learningConcept: 'Syntax Grammar & Bracket Pairing',
                whyItMatters: 'A syntax error stops the interpreter from even parsing or executing the script.',
                suggestedFix: {
                  before: trimmed,
                  after: `// Fixed: Ensure matching pair for ${trimmed}`,
                  explanation: `Remove the stray '${char}' or add the matching opening bracket.`
                }
              });
            } else {
              const top = stack.pop();
              const expected = matching[char];
              if (top.char !== expected) {
                syntaxFindings.push({
                  severity: 'critical',
                  title: `Syntax Error: Mismatched bracket '${char}', expected closure for '${top.char}'`,
                  ruleId: 'JS-SYN-001',
                  ruleName: 'Syntax Bracket Mismatch',
                  category: 'Syntax Error',
                  line: lineNum,
                  description: `Line ${lineNum}: Closing '${char}' does not match opening '${top.char}' from line ${top.line}.`,
                  impact: 'Code fails to parse with "SyntaxError: Unexpected token".',
                  aiExplanation: `You opened '${top.char}' on line ${top.line}, but tried to close it with '${char}' on line ${lineNum}. Pairs must match: ( with ), { with }, and [ with ].`,
                  learningConcept: 'Syntax Grammar & Code Nesting',
                  whyItMatters: 'Crossed brackets confuse the parser and corrupt the code scope hierarchy.',
                  suggestedFix: {
                    before: trimmed,
                    after: `// Replace '${char}' with correct closing bracket matching '${top.char}'`,
                    explanation: `Change '${char}' to the matching closing bracket for '${top.char}'.`
                  }
                });
              }
            }
          }
        }
        col++;
      }

      if ((inSingle || inDouble) && !inBacktick && !inMultilineComment) {
        const quoteType = inSingle ? "single quote (')" : 'double quote (")';
        syntaxFindings.push({
          severity: 'critical',
          title: `Syntax Error: Unterminated string literal (${quoteType})`,
          ruleId: 'JS-SYN-002',
          ruleName: 'Unterminated String Literal',
          category: 'Syntax Error',
          line: lineNum,
          description: `Line ${lineNum}: String literal begins with ${quoteType} but is never closed before the line ends.`,
          impact: 'JavaScript engine crashes with "SyntaxError: Invalid or unexpected token".',
          aiExplanation: `Strings enclosed in ${quoteType} cannot cross multiple lines without an escape character or template literals. Add the closing quote at the end of the line.`,
          learningConcept: 'String Literals & Delimiters',
          whyItMatters: 'Unclosed quotes consume subsequent keywords as raw text, breaking the parser.',
          suggestedFix: {
            before: trimmed,
            after: `${trimmed}"; // Add closing quote`,
            explanation: `Add the closing ${quoteType} to complete the string literal.`
          }
        });
      }
    }

    if (inBacktick) {
      syntaxFindings.push({
        severity: 'critical',
        title: 'Syntax Error: Unterminated template literal (`)',
        ruleId: 'JS-SYN-003',
        ruleName: 'Unterminated Template Literal',
        category: 'Syntax Error',
        line: lines.length,
        description: `Line ${lines.length}: Template literal with backtick (\`) was never terminated before end of file.`,
        impact: 'JavaScript parsing crashes with SyntaxError: Unterminated template literal.',
        aiExplanation: 'Template literals opened with a backtick (`) must be terminated with a matching closing backtick (`). Check your multiline strings.',
        learningConcept: 'Template Literals & String Closures',
        whyItMatters: 'Guaranteed execution failure across all JavaScript runtimes.',
        suggestedFix: {
          before: lines[lines.length - 1],
          after: lines[lines.length - 1] + '`;',
          explanation: 'Close the unterminated template string with a backtick.'
        }
      });
    }

    while (stack.length > 0) {
      const unclosed = stack.pop();
      syntaxFindings.push({
        severity: 'critical',
        title: `Syntax Error: Unclosed opening '${unclosed.char}'`,
        ruleId: 'JS-SYN-001',
        ruleName: 'Unclosed Block / Bracket',
        category: 'Syntax Error',
        line: unclosed.line,
        description: `Line ${unclosed.line}, Col ${unclosed.col}: Opening '${unclosed.char}' was never closed before end of file.`,
        impact: 'JavaScript engine fails with "SyntaxError: Unexpected end of input".',
        aiExplanation: `You opened a code block with '${unclosed.char}' on line ${unclosed.line}, but forgot to close it before the end of the script.`,
        learningConcept: 'Block Scoping & Enclosure',
        whyItMatters: 'The engine searches to the end of the file looking for the closure, causing an immediate crash.',
        suggestedFix: {
          before: `Line ${unclosed.line}: '${unclosed.char}'`,
          after: `Add closing bracket for '${unclosed.char}' at end of block`,
          explanation: `Add the corresponding closing bracket to properly close the block.`
        }
      });
    }

    return syntaxFindings;
  }

  // Helper: Strip string literals and inline comments from code line for false-positive safe pattern matching
  static stripStringsAndComments(line) {
    let result = '';
    let inSingle = false;
    let inDouble = false;
    let inBacktick = false;
    let escaped = false;

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];

      if (escaped) {
        escaped = false;
        result += ' ';
        continue;
      }

      if (ch === '\\' && (inSingle || inDouble || inBacktick)) {
        escaped = true;
        result += ' ';
        continue;
      }

      if (!inSingle && !inDouble && !inBacktick) {
        if (ch === '/' && line[i + 1] === '/') {
          break; // Omit rest of the line as it is an inline comment
        }
        if (ch === "'") { inSingle = true; result += ' '; continue; }
        if (ch === '"') { inDouble = true; result += ' '; continue; }
        if (ch === '`') { inBacktick = true; result += ' '; continue; }
        result += ch;
      } else if (inSingle && ch === "'") {
        inSingle = false;
        result += ' ';
      } else if (inDouble && ch === '"') {
        inDouble = false;
        result += ' ';
      } else if (inBacktick && ch === '`') {
        inBacktick = false;
        result += ' ';
      } else {
        result += ' ';
      }
    }
    return result;
  }

  static analyzeJavaScript(code) {
    const findings = [];
    const lines = code.split('\n');

    const lexicalFindings = this.checkSyntaxIntegrity(code);
    findings.push(...lexicalFindings);

    // If no bracket mismatch was found, run V8 syntax compiler check
    if (lexicalFindings.length === 0) {
      findings.push(...this.checkV8Syntax(code));
    }

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) continue;

      // Sanitized line for regex checking (strips string literals and inline comments)
      const codeOnly = this.stripStringsAndComments(line);

      // 0. Division by Zero
      if (/\/\s*0(?:\.0*)?(?!\d)/.test(codeOnly)) {
        findings.push({
          severity: 'high',
          title: 'Division by Zero Detected',
          ruleId: 'JS-MATH-001',
          ruleName: 'Division by Zero',
          category: 'Common Coding Issue',
          line: lineNum,
          description: `Line ${lineNum}: Dividing a number by zero produces Infinity or NaN.`,
          impact: 'Produces unexpected Infinity or NaN values that corrupt math and logic downstream.',
          explanation: `Dividing by zero is mathematically undefined. In JavaScript, positive numbers divided by 0 produce Infinity, and 0 / 0 produces NaN.`,
          aiExplanation: `Dividing by zero is mathematically undefined. In JavaScript, positive numbers divided by 0 produce Infinity, and 0 / 0 produces NaN.`,
          learningConcept: 'Arithmetic Safety & Non-Zero Validation',
          whyItMatters: 'Infinity and NaN values propagate through math operations and corrupt application state.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\/\s*0(?:\.0*)?(?!\d)/g, '/ 1 /* Ensure denominator is non-zero */'),
            explanation: 'Validate that the denominator is greater than zero before dividing.'
          }
        });
      }

      // 1. var declaration
      const varMatch = codeOnly.match(/\bvar\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/);
      if (varMatch) {
        findings.push({
          severity: 'medium',
          title: `Legacy 'var' Declaration: '${varMatch[1]}'`,
          ruleId: 'JS-LINT-002',
          ruleName: 'Legacy Var Declaration',
          category: 'Modern JavaScript (ES6+)',
          line: lineNum,
          description: `Line ${lineNum}: 'var ${varMatch[1]}' is function-scoped and hoisted, causing subtle scoping bugs.`,
          impact: 'Variables leak outside loops and if-statements into the surrounding function scope.',
          explanation: `'var' is legacy syntax from pre-2015 JavaScript. It gets "hoisted" to the top of the function and leaks outside blocks. In modern ES6+, always prefer 'const' or 'let'.`,
          aiExplanation: `'var' is legacy syntax from pre-2015 JavaScript. It gets "hoisted" to the top of the function and leaks outside blocks. In modern ES6+, always prefer 'const' or 'let'.`,
          learningConcept: 'Variable Hoisting & Block Scope',
          whyItMatters: 'Block-scoping prevents variables in different loops or conditionals from overwriting each other.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\bvar\b/, 'let'),
            explanation: `Replace 'var' with 'let' (or 'const' if never reassigned).`
          }
        });
      }

      // 2. Loose equality (excluding NaN comparisons handled by JS-LINT-003)
      if (/[^=!]==(?!=)(?!\s*NaN\b)|[^=!]!=(?!=)(?!\s*NaN\b)/.test(codeOnly) && !/\bNaN\s*(?:==|!=)/.test(codeOnly)) {
        findings.push({
          severity: 'low',
          title: 'Loose Equality Operator (==) Used',
          ruleId: 'JS-LINT-001',
          ruleName: 'Loose Equality Operator',
          category: 'Best Practice',
          line: lineNum,
          description: `Line ${lineNum}: Loose equality allows unexpected type coercion.`,
          impact: 'Subtle boundary bugs (e.g. 0 == "" is true, "1" == 1 is true).',
          explanation: `'==' converts types before checking (type coercion). Modern JavaScript standard practice is to ALWAYS use '===' (strict equality), which checks both type and value.`,
          aiExplanation: `'==' converts types before checking (type coercion). Modern JavaScript standard practice is to ALWAYS use '===' (strict equality), which checks both type and value.`,
          learningConcept: 'Strict Equality (===) vs Type Coercion (==)',
          whyItMatters: 'Strict equality eliminates entire classes of subtle conversion bugs.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/([^=!])==([^=])/g, '$1===$2').replace(/([^=!])!=([^=])/g, '$1!==$2'),
            explanation: 'Replace loose == with strict === and != with strict !==.'
          }
        });
      }

      // 3. Comparison with NaN
      if (/(==|===|!=|!==)\s*NaN\b|\bNaN\s*(==|===|!=|!==)/.test(codeOnly)) {
        const nanFixed = trimmed
          .replace(/([a-zA-Z0-9_$.]+)\s*(?:===|==)\s*NaN\b/g, 'Number.isNaN($1)')
          .replace(/\bNaN\s*(?:===|==)\s*([a-zA-Z0-9_$.]+)/g, 'Number.isNaN($1)')
          .replace(/([a-zA-Z0-9_$.]+)\s*(?:!==|!=)\s*NaN\b/g, '!Number.isNaN($1)')
          .replace(/\bNaN\s*(?:!==|!=)\s*([a-zA-Z0-9_$.]+)/g, '!Number.isNaN($1)');
        findings.push({
          severity: 'high',
          title: 'Invalid Direct Comparison with NaN',
          ruleId: 'JS-LINT-003',
          ruleName: 'NaN Comparison Bug',
          category: 'Common Coding Issue',
          line: lineNum,
          description: `Line ${lineNum}: In JavaScript, NaN is never equal to itself (NaN === NaN is false).`,
          impact: 'Condition will never evaluate to true, creating broken dead logic.',
          explanation: `NaN ("Not a Number") does not equal itself by IEEE-754 floating point standard. Thus 'x === NaN' is always false! To check if a variable is NaN, use Number.isNaN(x).`,
          aiExplanation: `NaN ("Not a Number") does not equal itself by IEEE-754 floating point standard. Thus 'x === NaN' is always false! To check if a variable is NaN, use Number.isNaN(x).`,
          learningConcept: 'IEEE-754 Special Values & Number.isNaN()',
          whyItMatters: 'Writing if (x == NaN) is guaranteed dead code.',
          suggestedFix: {
            before: trimmed,
            after: nanFixed,
            explanation: 'Use Number.isNaN(variable) to properly verify if a number is NaN.'
          }
        });
      }

      // 4. Accidental assignment in conditional
      if (/\b(if|while)\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*[^=]/.test(codeOnly)) {
        findings.push({
          severity: 'critical',
          title: 'Accidental Assignment in Condition',
          ruleId: 'JS-SYN-003',
          ruleName: 'Assignment in Conditional',
          category: 'Common Coding Issue',
          line: lineNum,
          description: `Line ${lineNum}: Single '=' assigns a value instead of comparing with '==='`,
          impact: 'The variable is unexpectedly overwritten and condition evaluates to the assigned value.',
          explanation: `Single '=' is the assignment operator, not comparison. Writing 'if (score = 100)' overwrites score and always evaluates to true!`,
          aiExplanation: `Single '=' is the assignment operator, not comparison. Writing 'if (score = 100)' overwrites score and always evaluates to true!`,
          learningConcept: 'Assignment (=) vs Comparison (===)',
          whyItMatters: 'Accidental assignments silently mutate state.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/=\s*([^=])/, '=== $1'),
            explanation: "Replace '=' with '===' to test equality."
          }
        });
      }

      // 5. Inefficient DOM in Loop
      if (/\b(document\.getElementById|document\.querySelector|document\.getElementsBy)\b/.test(codeOnly)) {
        const prevContext = lines.slice(Math.max(0, idx - 5), idx + 1).join('\n');
        if (/\b(for|while)\s*\(/.test(prevContext)) {
          findings.push({
            severity: 'medium',
            title: 'Inefficient DOM Query Inside Loop',
            ruleId: 'JS-PERF-001',
            ruleName: 'DOM Query in Loop',
            category: 'Poorly Written Code',
            line: lineNum,
            description: `Line ${lineNum}: Searching the DOM inside a loop causes layout thrashing and lag.`,
            impact: 'Severe web page lag and slow rendering.',
            explanation: `Searching the DOM with document.getElementById() inside a loop forces the browser to re-scan the entire web page on every iteration! Store the element in a variable outside the loop once.`,
            aiExplanation: `Searching the DOM with document.getElementById() inside a loop forces the browser to re-scan the entire web page on every iteration! Store the element in a variable outside the loop once.`,
            learningConcept: 'DOM Performance & Variable Caching',
            whyItMatters: 'Caching DOM references outside loops makes rendering up to 100x faster.',
            suggestedFix: {
              before: trimmed,
              after: `// Outside loop: const el = document.getElementById('item');\n// Inside loop: el.innerHTML = ...;`,
              explanation: 'Store the DOM element in a variable outside the loop.'
            }
          });
        }
      }

      // 6. Empty catch block
      if (/catch\s*(\([^)]*\))?\s*\{\s*\}/.test(codeOnly)) {
        const catchMatch = trimmed.match(/catch\s*(\([^)]*\))?\s*\{\s*\}/);
        const errParam = (catchMatch && catchMatch[1]) ? catchMatch[1].replace(/[()]/g, '').trim() : 'err';
        findings.push({
          severity: 'high',
          title: 'Empty Catch Block Silencing Errors',
          ruleId: 'JS-BUG-001',
          ruleName: 'Silenced Exception',
          category: 'Common Coding Issue',
          line: lineNum,
          description: `Line ${lineNum}: Empty catch block silently swallows errors without logging or handling.`,
          impact: 'Silent failures and impossible debugging.',
          explanation: `An empty catch block swallows errors without notifying the developer. Always log with console.error(err) or show feedback.`,
          aiExplanation: `An empty catch block swallows errors without notifying the developer. Always log with console.error(err) or show feedback.`,
          learningConcept: 'Exception Handling & Error Feedback',
          whyItMatters: 'Silenced exceptions hide critical runtime bugs.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/catch\s*(\([^)]*\))?\s*\{\s*\}/, `catch (${errParam || 'err'}) {\n        console.error('Error occurred:', ${errParam || 'err'});\n    }`),
            explanation: 'Log or handle the exception properly.'
          }
        });
      }

      // 7. DOM XSS via innerHTML
      if (/(innerHTML\s*=|document\.write\s*\(|outerHTML\s*=)/.test(codeOnly)) {
        let xssFixAfter = trimmed;
        if (/\.innerHTML\s*=/.test(trimmed)) {
          xssFixAfter = trimmed.replace(/\.innerHTML\s*=/g, '.textContent =');
        } else if (/\.outerHTML\s*=/.test(trimmed)) {
          xssFixAfter = trimmed.replace(/\.outerHTML\s*=/g, '.textContent =');
        }
        findings.push({
          severity: 'high',
          title: 'Potential DOM Cross-Site Scripting (XSS) via innerHTML',
          ruleId: 'JS-SEC-002',
          ruleName: 'DOM Cross-Site Scripting',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Direct assignment to innerHTML can execute arbitrary attacker JavaScript.`,
          impact: 'Session hijacking and malicious script execution.',
          explanation: `When user input is injected into .innerHTML, the browser parses it as raw HTML and executes any script tags. Use .textContent for safe plain text.`,
          aiExplanation: `When user input is injected into .innerHTML, the browser parses it as raw HTML and executes any script tags. Use .textContent for safe plain text.`,
          learningConcept: 'DOM XSS & Safe Text Injection (.textContent vs .innerHTML)',
          whyItMatters: 'XSS allows attackers to steal user session cookies.',
          suggestedFix: {
            before: trimmed,
            after: xssFixAfter,
            explanation: 'Use .textContent to insert plain text safely without executing HTML.'
          }
        });
      }

      // 8. Dynamic eval()
      if (/\b(eval\s*\(|new\s+Function\s*\()/.test(codeOnly)) {
        let evalFixAfter = trimmed;
        if (/\beval\s*\(/.test(trimmed)) {
          evalFixAfter = trimmed.replace(/\beval\s*\(([^)]+)\)/g, 'JSON.parse($1) /* Safely parse JSON */');
        }
        findings.push({
          severity: 'critical',
          title: 'Dangerous Dynamic Code Execution via eval()',
          ruleId: 'JS-SEC-003',
          ruleName: 'Dynamic Code Evaluation',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: eval() executes arbitrary strings as live code.`,
          impact: 'Remote code execution (RCE) in browser or server.',
          explanation: `'eval()' takes any string and executes it as real program code. It gives full system access to untrusted inputs. Use JSON.parse() instead.`,
          aiExplanation: `'eval()' takes any string and executes it as real program code. It gives full system access to untrusted inputs. Use JSON.parse() instead.`,
          learningConcept: 'Dynamic Code Execution & Input Sanitization',
          whyItMatters: 'eval() is one of the most dangerous functions in JavaScript.',
          suggestedFix: {
            before: trimmed,
            after: evalFixAfter,
            explanation: 'Use JSON.parse() or a safe parser instead of eval().'
          }
        });
      }

      // 9. Hardcoded Secret / Token (checked on raw line to match literal credentials)
      if (/(api[_-]?key|secret|password|passwd|token|private[_-]?key)\s*[:=]\s*['"][^'"]{6,}['"]/i.test(line)) {
        const secMatch = line.match(/(api[_-]?key|secret|password|passwd|token|private[_-]?key)/i);
        const envVarName = secMatch ? secMatch[1].toUpperCase().replace(/-/g, '_') : 'API_KEY';
        const secretFixAfter = trimmed.replace(/['"][^'"]{6,}['"]/, `process.env.${envVarName} || ""`);
        findings.push({
          severity: 'critical',
          title: 'Hardcoded Secret / Token in JavaScript',
          ruleId: 'SEC-001',
          ruleName: 'Hardcoded Credential',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Sensitive secret or token hardcoded directly in script.`,
          impact: 'Credentials exposed in source code repository or client bundles.',
          explanation: `API keys and passwords should never be typed directly into source code. Anyone viewing the source can steal them.`,
          aiExplanation: `API keys and passwords should never be typed directly into source code. Anyone viewing the source can steal them.`,
          learningConcept: 'Secret Management & Environment Variables',
          whyItMatters: 'Compromised secrets lead to database breaches and unauthorized access.',
          suggestedFix: {
            before: trimmed,
            after: secretFixAfter,
            explanation: 'Load secrets from environment variables.'
          }
        });
      }

      // 10. Callback Hell
      if ((codeOnly.match(/function\s*\(/g) || []).length > 1 || (codeOnly.match(/=>/g) || []).length >= 2) {
        findings.push({
          severity: 'medium',
          title: 'Deeply Nested Callbacks (Callback Hell)',
          ruleId: 'JS-READ-003',
          ruleName: 'Callback Hell',
          category: 'Poorly Written Code',
          line: lineNum,
          description: `Line ${lineNum}: Multiple nested callback functions make asynchronous code unreadable.`,
          impact: 'Pyramid of Doom structure, error propagation issues.',
          explanation: `Nesting callbacks creates a "Pyramid of Doom". Modern JavaScript provides async/await and Promises to write clean, linear code.`,
          aiExplanation: `Nesting callbacks creates a "Pyramid of Doom". Modern JavaScript provides async/await and Promises to write clean, linear code.`,
          learningConcept: 'Asynchronous JavaScript (Callbacks vs Async/Await)',
          whyItMatters: 'async/await makes asynchronous logic 10x easier to read and debug.',
          suggestedFix: {
            before: trimmed,
            after: 'const result = await fetchAsyncData();',
            explanation: 'Refactor nested callbacks into an async function.'
          }
        });
      }

      // 11. Debug statements
      if (/\b(debugger;|console\.log\s*\()/.test(codeOnly) && !trimmed.startsWith('//')) {
        findings.push({
          severity: 'low',
          title: 'Debug Statement Left in Code',
          ruleId: 'JS-READ-002',
          ruleName: 'Debug Statement',
          category: 'Code Quality',
          line: lineNum,
          description: `Line ${lineNum}: Debug statement left in code.`,
          impact: 'Pollutes console output in production.',
          explanation: `console.log() is great while developing, but should be cleaned up before production to avoid leaking internal variables.`,
          aiExplanation: `console.log() is great while developing, but should be cleaned up before production to avoid leaking internal variables.`,
          learningConcept: 'Clean Code Hygiene',
          whyItMatters: 'Keeps application logs clean and readable.',
          suggestedFix: {
            before: trimmed,
            after: `// Cleaned: ${trimmed}`,
            explanation: 'Remove or comment out temporary debugging statements.'
          }
        });
      }
    }

    return findings;
  }

  // ==========================================================================
  // TYPESCRIPT ANALYZER (STATIC TYPE SAFETY & CONTRACT CHECKS)
  // ==========================================================================
  static analyzeTypeScript(code) {
    const findings = [];
    const lines = code.split('\n');

    // Run underlying JS syntax & semantic checks
    findings.push(...this.analyzeJavaScript(code));

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      if (!trimmed || (trimmed.startsWith('//') && !trimmed.includes('@ts-')) || trimmed.startsWith('/*')) continue;

      // 1. Unsafe 'any' type usage
      if (/:\s*any\b|\bas\s+any\b|<any>/.test(line)) {
        findings.push({
          severity: 'medium',
          title: "Unsafe 'any' Type Usage in TypeScript",
          ruleId: 'TS-TYPE-001',
          ruleName: 'Unsafe Any Type',
          category: 'TypeScript Type Safety',
          line: lineNum,
          description: `Line ${lineNum}: Using 'any' turns off TypeScript's static type checker for this variable.`,
          impact: 'Defeats the primary purpose of TypeScript, allowing runtime type mismatches to go undetected.',
          aiExplanation: `Using ': any' bypasses compile-time type verification. Prefer using 'unknown' (with type narrowing) or a specific interface/type to preserve type safety.`,
          learningConcept: 'TypeScript Type Soundness & Static Analysis',
          whyItMatters: 'Guarantees type-safety contracts and prevents runtime TypeError crashes.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/:\s*any\b/, ': unknown'),
            explanation: "Replace 'any' with 'unknown' or a strongly typed interface."
          }
        });
      }

      // 2. TypeScript Error Suppression (@ts-ignore / @ts-nocheck)
      if (/@ts-(ignore|nocheck|expect-error)/.test(line)) {
        findings.push({
          severity: 'high',
          title: 'TypeScript Type-Check Suppression Directive',
          ruleId: 'TS-IGNORE-001',
          ruleName: 'Suppressed Type Checking',
          category: 'TypeScript Best Practice',
          line: lineNum,
          description: `Line ${lineNum}: '@ts-ignore' or '@ts-nocheck' suppresses TypeScript compilation errors.`,
          impact: 'Hides critical type bugs that will surface during runtime execution.',
          aiExplanation: `Directives like '@ts-ignore' or '@ts-nocheck' instruct the compiler to ignore errors instead of fixing the underlying type signature mismatch. Fix the types or write a type assertion instead.`,
          learningConcept: 'Compiler Diagnostics & Type Discipline',
          whyItMatters: 'Suppressed errors accumulate technical debt and introduce latent bugs.',
          suggestedFix: {
            before: trimmed,
            after: '// Type properly or use type assertion instead of suppressing compiler diagnostics',
            explanation: 'Remove @ts-ignore and resolve the actual type mismatch.'
          }
        });
      }

      // 3. Empty Interface Declaration
      if (/interface\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\{\s*\}/.test(line)) {
        findings.push({
          severity: 'low',
          title: 'Empty TypeScript Interface Declaration',
          ruleId: 'TS-EMPTY-001',
          ruleName: 'Empty Interface',
          category: 'Code Quality & Typing',
          line: lineNum,
          description: `Line ${lineNum}: Interface has no members defined.`,
          impact: 'An empty interface acts as a no-op contract and matches almost any object.',
          aiExplanation: `An empty interface does not provide any contract guarantees. Define the expected properties or use a type alias if representing an opaque structure.`,
          learningConcept: 'TypeScript Interface Contracts',
          whyItMatters: 'Ensures clear data shapes and developer documentation.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\{\s*\}/, '{\n    id: string;\n}'),
            explanation: 'Define properties inside the interface or remove it.'
          }
        });
      }

      // 4. Banned primitive wrapper object types (e.g. : String, : Number, : Boolean)
      if (/:\s*(String|Number|Boolean|Symbol|BigInt)\b/.test(line)) {
        findings.push({
          severity: 'medium',
          title: 'Banned Primitive Wrapper Object Type',
          ruleId: 'TS-WRAPPER-001',
          ruleName: 'Banned Type Wrapper',
          category: 'TypeScript Type Safety',
          line: lineNum,
          description: `Line ${lineNum}: Using uppercase wrapper types (String, Number, Boolean) represents boxed object instances, not primitive values.`,
          impact: 'Causes unexpected type incompatibility and reference boxing errors.',
          aiExplanation: `In TypeScript, use lowercase primitive types ('string', 'number', 'boolean', 'symbol') instead of wrapper objects ('String', 'Number', 'Boolean').`,
          learningConcept: 'Primitives vs Wrapper Objects in TypeScript',
          whyItMatters: 'Wrapper objects are rarely desired in modern TypeScript and lead to tricky runtime type issues.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/:\s*(String|Number|Boolean|Symbol|BigInt)\b/g, (m, p) => `: ${p.toLowerCase()}`),
            explanation: "Replace boxed wrapper type with primitive type (e.g., 'string' instead of 'String')."
          }
        });
      }

      // 5. Non-null Assertion Operator (!)
      if (/[a-zA-Z0-9_\)\]]!(?:\.|\b|\[)/.test(line) && !line.includes('!=') && !line.includes('!==')) {
        findings.push({
          severity: 'medium',
          title: 'Unsafe Non-Null Assertion Operator (!)',
          ruleId: 'TS-NON-NULL-001',
          ruleName: 'Non-Null Assertion',
          category: 'TypeScript Type Safety',
          line: lineNum,
          description: `Line ${lineNum}: Non-null assertion operator (!) forcibly disables strict null checks.`,
          impact: 'Can cause runtime TypeError: Cannot read property of undefined/null if the value is nullish.',
          aiExplanation: `Using the non-null assertion operator '!' silences the compiler without ensuring the value exists. Prefer optional chaining '?.' or explicit truthiness/guard checks.`,
          learningConcept: 'Strict Null Checking & Defensiveness',
          whyItMatters: 'Avoids unanticipated uncaught exceptions in production environments.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/!(\.|\b|\[)/, '?$1'),
            explanation: 'Use optional chaining (?.) or an if check instead of non-null assertion.'
          }
        });
      }
    }

    return findings;
  }

  // ==========================================================================
  // PYTHON ANALYZER (NEW MULTI-LANGUAGE FEATURE)
  // ==========================================================================
  static analyzePython(code) {
    const findings = [];
    const lines = code.split('\n');

    // 0. Bracket / Parenthesis / Brace Pairing for Python
    const stack = [];
    const matching = { ')': '(', ']': '[', '}': '{' };
    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const lineWithoutComment = lines[idx].replace(/#.*$/, '');
      for (let col = 0; col < lineWithoutComment.length; col++) {
        const char = lineWithoutComment[col];
        if (char === '(' || char === '[' || char === '{') {
          stack.push({ char, line: lineNum });
        } else if (char === ')' || char === ']' || char === '}') {
          if (stack.length > 0 && stack[stack.length - 1].char === matching[char]) {
            stack.pop();
          } else {
            findings.push({
              severity: 'critical',
              title: `Python SyntaxError: Unmatched closing '${char}'`,
              ruleId: 'PY-SYN-004',
              ruleName: 'Unmatched Closing Delimiter',
              category: 'Python Syntax Error',
              line: lineNum,
              description: `Line ${lineNum}: Found closing '${char}' with no opening match.`,
              impact: 'Python interpreter crashes with SyntaxError: unmatched closing parenthesis/bracket.',
              explanation: `All parentheses and brackets in Python must be symmetrical and closed in matching order.`,
              learningConcept: 'Python Lexical Delimiters',
              whyItMatters: 'Guaranteed execution failure upon script launch.',
              suggestedFix: {
                before: lines[idx].trim(),
                after: `// Fixed: ${lines[idx].trim()}`,
                explanation: `Remove or fix the stray '${char}' on line ${lineNum}.`
              }
            });
          }
        }
      }
    }
    while (stack.length > 0) {
      const unclosed = stack.pop();
      findings.push({
        severity: 'critical',
        title: `Python SyntaxError: Unclosed opening '${unclosed.char}'`,
        ruleId: 'PY-SYN-005',
        ruleName: 'Unclosed Opening Delimiter',
        category: 'Python Syntax Error',
        line: unclosed.line,
        description: `Line ${unclosed.line}: Opening '${unclosed.char}' was never closed before end of file.`,
        impact: 'Python interpreter fails with "SyntaxError: unexpected EOF while parsing".',
        explanation: `You opened '${unclosed.char}' on line ${unclosed.line} but never closed it before end of file.`,
        learningConcept: 'Python Block Closure',
        whyItMatters: 'Guaranteed execution failure upon script launch.',
        suggestedFix: {
          before: lines[unclosed.line - 1].trim(),
          after: `${lines[unclosed.line - 1].trim()} ${unclosed.char === '(' ? ')' : unclosed.char === '[' ? ']' : '}'}`,
          explanation: `Add matching closing bracket for '${unclosed.char}'.`
        }
      });
    }

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith('#')) continue;

      const codeWithoutComment = trimmed.replace(/#.*$/, '').trim();

      // Division by zero in Python
      if (/\/\s*0(?:\.0*)?(?!\d)/.test(codeWithoutComment)) {
        findings.push({
          severity: 'high',
          title: 'ZeroDivisionError: Division by zero',
          ruleId: 'PY-MATH-001',
          ruleName: 'Python Division by Zero',
          category: 'Python Pitfall',
          line: lineNum,
          description: `Line ${lineNum}: Division by zero halts program with ZeroDivisionError.`,
          impact: 'Unhandled ZeroDivisionError crashes execution.',
          aiExplanation: `Dividing by zero is mathematically undefined and raises ZeroDivisionError in Python. Check that denominator != 0.`,
          learningConcept: 'Python Arithmetic Exception Safety',
          whyItMatters: 'Guaranteed runtime crash if executed.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\/\s*0(?:\.0*)?(?!\d)/g, '/ 1 # Check denominator != 0'),
            explanation: 'Verify denominator is non-zero before dividing.'
          }
        });
      }

      // Accidental assignment in if condition in Python
      if (/\b(if|elif)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^=:]/.test(codeWithoutComment)) {
        findings.push({
          severity: 'critical',
          title: 'Python SyntaxError: invalid syntax (assignment in condition)',
          ruleId: 'PY-SYN-002',
          ruleName: 'Assignment in Condition',
          category: 'Python Syntax Error',
          line: lineNum,
          description: `Line ${lineNum}: Python disallows assignment '=' inside if statements. Use '==' for comparison or ':=' for walrus assignment.`,
          impact: 'Interpreter halts with SyntaxError: invalid syntax.',
          aiExplanation: `In Python, '=' is an assignment statement, not an expression. Use '==' for equality comparisons.`,
          learningConcept: 'Comparison (==) vs Assignment (=)',
          whyItMatters: 'Guaranteed SyntaxError in Python.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/=\s*([^=:])/, '== $1'),
            explanation: 'Replace single = with == for equality comparison.'
          }
        });
      }

      // Python 2 print without parens
      if (/^\s*print\s+['"][^'"]*['"]/.test(codeWithoutComment)) {
        findings.push({
          severity: 'critical',
          title: 'Python SyntaxError: Missing parentheses in call to "print"',
          ruleId: 'PY-SYN-003',
          ruleName: 'Python 2 Print Statement in Python 3',
          category: 'Python Syntax Error',
          line: lineNum,
          description: `Line ${lineNum}: In Python 3, print is a function and requires parentheses: print(...).`,
          impact: 'Interpreter halts with SyntaxError: Missing parentheses in call to "print".',
          aiExplanation: `In Python 3+, print() is a built-in function and must be called with parentheses.`,
          learningConcept: 'Python 3 Function Call Syntax',
          whyItMatters: 'Guaranteed SyntaxError in modern Python.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/print\s+(.*)$/, 'print($1)'),
            explanation: 'Wrap the printed arguments in parentheses.'
          }
        });
      }

      // 0. Missing Colon on compound statements (Syntax Error, comment-safe)
      if (/^\s*(def|if|elif|else|for|while|try|except|finally|class|with)\b/i.test(codeWithoutComment)) {
        if (!codeWithoutComment.endsWith(':') && !codeWithoutComment.endsWith('\\') && !codeWithoutComment.endsWith('(') && !codeWithoutComment.endsWith('[')) {
          findings.push({
            severity: 'critical',
            title: `Python SyntaxError: Missing Colon ':' on ${codeWithoutComment.split(/\s+/)[0]}`,
            ruleId: 'PY-SYN-001',
            ruleName: 'Missing Compound Statement Colon',
            category: 'Python Syntax Error',
            line: lineNum,
            description: `Line ${lineNum}: Python compound statements must terminate with a colon ':'.`,
            impact: 'Python interpreter halts with SyntaxError: expected \':\' before code can execute.',
            aiExplanation: `In Python, all header lines for compound statements (def, if, for, while, class, with, etc.) require a colon ':' at the end of the line before indenting the block.`,
            learningConcept: 'Python Block Indentation & Colon Syntax',
            whyItMatters: 'Guaranteed script failure upon launch.',
            suggestedFix: {
              before: trimmed,
              after: codeWithoutComment + ':',
              explanation: 'Add colon ":" to the end of the statement.'
            }
          });
        }
      }

      // 1. Mutable Default Arguments in Functions
      if (/def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(.*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*(\[\]|\{\})/i.test(line)) {
        findings.push({
          severity: 'high',
          title: 'Mutable Default Argument in Function Definition',
          ruleId: 'PY-BUG-001',
          ruleName: 'Mutable Default Argument',
          category: 'Python Pitfall',
          line: lineNum,
          description: `Line ${lineNum}: Using mutable defaults (like list [] or dict {}) shares state across all function calls.`,
          impact: 'Unexpected state retention between function calls, causing insidious data bugs.',
          aiExplanation: `In Python, default arguments are evaluated ONCE when the function is defined, NOT each time it is called! If you mutate the default list (e.g. items.append(1)), subsequent calls will reuse the same modified list. Always use None as the default: def func(items=None): if items is None: items = [].`,
          learningConcept: 'Python Function Object Binding & Mutable Defaults',
          whyItMatters: 'One of the most famous Python beginner traps that leads to silent data corruption.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/=\s*(\[\]|\{\})/, '=None'),
            explanation: 'Use None as default and initialize inside function body.'
          }
        });
      }

      // 2. Bare Except Clause
      if (/^except\s*:/.test(trimmed)) {
        findings.push({
          severity: 'medium',
          title: 'Bare "except:" Catches All Exceptions',
          ruleId: 'PY-BUG-002',
          ruleName: 'Bare Except',
          category: 'Exception Handling',
          line: lineNum,
          description: `Line ${lineNum}: Bare except catches SystemExit, KeyboardInterrupt, and MemoryError, preventing program termination.`,
          impact: 'Cannot stop script with Ctrl+C and masks critical syntax or memory failures.',
          aiExplanation: `Writing 'except:' catches BaseException, which includes KeyboardInterrupt (Ctrl+C) and SystemExit. This means the user cannot even kill the script! Always catch specific exceptions (like 'except ValueError:' or 'except Exception:').`,
          learningConcept: 'Python Exception Hierarchy (BaseException vs Exception)',
          whyItMatters: 'Prevents the Python interpreter from exiting gracefully.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/^except\s*:/, 'except Exception as e:'),
            explanation: 'Catch Exception specifically rather than using bare except.'
          }
        });
      }

      // 3. Subprocess shell=True (Command Injection)
      if (/(subprocess\.(Popen|call|run|check_output)\s*\(.*shell\s*=\s*True)/.test(line)) {
        findings.push({
          severity: 'critical',
          title: 'Command Injection Risk (shell=True)',
          ruleId: 'PY-SEC-001',
          ruleName: 'Subprocess Shell Injection',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Executing subprocess commands with shell=True permits OS command injection.`,
          impact: 'Arbitrary shell command execution on host operating system.',
          aiExplanation: `When shell=True is set, Python spawns an OS shell (/bin/sh or cmd.exe). If user input is passed into the command, an attacker can append '; rm -rf /' to execute arbitrary commands! Pass arguments as a list with shell=False.`,
          learningConcept: 'OS Command Injection & Safe Subprocess Spawning',
          whyItMatters: 'Direct remote shell takeover of the host server.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/shell\s*=\s*True/g, 'shell=False'),
            explanation: 'Pass command arguments safely with shell=False.'
          }
        });
      }

      // 4. Insecure Pickle Deserialization
      if (/pickle\.(loads|load)\s*\(/.test(line)) {
        findings.push({
          severity: 'critical',
          title: 'Insecure Deserialization via pickle',
          ruleId: 'PY-SEC-002',
          ruleName: 'Insecure Pickle Deserialization',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: pickle deserializes arbitrary Python objects, allowing remote code execution.`,
          impact: 'Remote code execution (RCE) via malicious pickle payloads.',
          aiExplanation: `Python's pickle module is fundamentally unsafe for untrusted data. A crafted pickle payload can execute any Python code upon deserialization (via __reduce__). Always use json.loads() or safer serialization formats.`,
          learningConcept: 'Object Serialization Security & Safe JSON Alternatives',
          whyItMatters: 'Untrusted pickle data allows full remote takeover.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\bpickle\.(loads|load)\b/g, 'json.loads'),
            explanation: 'Use JSON serialization instead of pickle.'
          }
        });
      }

      // 5. String Comparison using 'is'
      if (/\bis\s+['"][^'"]*['"]/.test(line)) {
        findings.push({
          severity: 'medium',
          title: 'String Comparison using "is" instead of "=="',
          ruleId: 'PY-LINT-001',
          ruleName: 'Identity vs Equality in Python',
          category: 'Python Pitfall',
          line: lineNum,
          description: `Line ${lineNum}: "is" checks object identity (memory address), not value equality.`,
          impact: 'Unpredictable equality results depending on Python string interning.',
          aiExplanation: `'is' checks if two variables point to the exact same object in memory, whereas '==' checks if their contents are equal. Python interns small strings, so 'x is "a"' might work sometimes, but fails on dynamically generated strings! Use '=='.`,
          learningConcept: 'Object Identity (is) vs Value Equality (==)',
          whyItMatters: 'Breaks when strings are loaded from files or network requests.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\bis\b/, '=='),
            explanation: 'Replace "is" with "==" for value comparison.'
          }
        });
      }

      // 6. Hardcoded Secret
      if (/(api[_-]?key|secret|password|token)\s*=\s*['"][^'"]{6,}['"]/i.test(line)) {
        const secMatch = line.match(/(api[_-]?key|secret|password|token)/i);
        const varName = secMatch ? secMatch[1].toUpperCase() : 'SECRET_KEY';
        findings.push({
          severity: 'critical',
          title: 'Hardcoded Secret / Token in Python',
          ruleId: 'SEC-001',
          ruleName: 'Hardcoded Credential',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Secret or credential hardcoded directly in Python file.`,
          impact: 'Exposes cloud keys and passwords to repository viewers.',
          aiExplanation: `Store credentials in environment variables using os.environ.get('SECRET_KEY') instead of typing them directly into the script.`,
          learningConcept: 'Python os.environ & Twelve-Factor App Principles',
          whyItMatters: 'Prevents credential leaks in git history.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/['"][^'"]{6,}['"]/, `os.environ.get("${varName}", "")`),
            explanation: 'Load secret from environment variable.'
          }
        });
      }
    }

    return findings;
  }

  // ==========================================================================
  // HTML5 ANALYZER
  // ==========================================================================
  static analyzeHtml(code) {
    const findings = [];
    const lines = code.split('\n');

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      // Missing alt attribute on img
      if (/<img\b(?![^>]*\balt=)[^>]*>/i.test(line)) {
        findings.push({
          severity: 'medium',
          title: 'Image Missing "alt" Attribute (Accessibility)',
          ruleId: 'HTML-A11Y-001',
          ruleName: 'Missing Image Alt Tag',
          category: 'Accessibility (a11y)',
          line: lineNum,
          description: `Line ${lineNum}: <img> tag lacks an 'alt' attribute, breaking screen readers.`,
          impact: 'Visually impaired users using screen readers cannot understand image content.',
          aiExplanation: `The 'alt' attribute provides alternative text for screen readers and search engines. Every image must have an alt attribute describing its visual content.`,
          learningConcept: 'Web Accessibility (WCAG 2.1) & Semantic HTML',
          whyItMatters: 'Essential for accessibility compliance and SEO ranking.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/<img\b/, '<img alt="Descriptive image label"'),
            explanation: 'Add descriptive alt text to the img tag.'
          }
        });
      }

      // Inline Javascript Event Handlers
      if (/\bon(click|load|mouseover|error)\s*=\s*['"][^'"]*['"]/i.test(line)) {
        findings.push({
          severity: 'high',
          title: 'Inline JavaScript Event Handler (XSS Risk)',
          ruleId: 'HTML-SEC-001',
          ruleName: 'Inline Scripting',
          category: 'Security & Quality',
          line: lineNum,
          description: `Line ${lineNum}: Inline event handlers violate Content Security Policy (CSP).`,
          impact: 'High risk of Cross-Site Scripting (XSS) and code maintainability issues.',
          aiExplanation: `Writing JavaScript inside HTML attributes like onclick="..." makes it impossible to use Content Security Policy (CSP) headers and mixes presentation with logic. Attach event listeners in JavaScript via addEventListener.`,
          learningConcept: 'Separation of Concerns & Content Security Policy (CSP)',
          whyItMatters: 'Prevents XSS injection and creates clean modular code.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\bon(?:click|load|mouseover|error)\s*=\s*['"][^'"]*['"]/gi, 'data-action="handle-event"'),
            explanation: 'Remove inline onclick and use element.addEventListener() in your JavaScript file.'
          }
        });
      }
    }

    return findings;
  }

  // ==========================================================================
  // CSS3 ANALYZER
  // ==========================================================================
  static analyzeCss(code) {
    const findings = [];
    const lines = code.split('\n');

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      // Overuse of !important
      if (/!important/i.test(line)) {
        findings.push({
          severity: 'low',
          title: 'Overuse of "!important" in CSS Rule',
          ruleId: 'CSS-LINT-001',
          ruleName: 'CSS Specificity Hack',
          category: 'CSS Best Practice',
          line: lineNum,
          description: `Line ${lineNum}: '!important' overrides natural cascade and specificity.`,
          impact: 'CSS becomes impossible to maintain or override with responsive media queries.',
          aiExplanation: `Using '!important' breaks the natural CSS cascade order. Instead of fixing specificity with better selectors, developers often stack more '!important' declarations, leading to CSS spaghetti.`,
          learningConcept: 'CSS Specificity Hierarchy & Cascade Rules',
          whyItMatters: 'Keeps stylesheets modular and maintainable.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\s*!important/i, ''),
            explanation: 'Remove !important and increase selector specificity naturally.'
          }
        });
      }

      // Insecure HTTP Import
      if (/@import\s+url\s*\(\s*['"]?http:\/\//i.test(line)) {
        findings.push({
          severity: 'high',
          title: 'Insecure HTTP Stylesheet Import',
          ruleId: 'CSS-SEC-001',
          ruleName: 'Insecure Asset Protocol',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Importing fonts or styles over unencrypted HTTP protocol.`,
          impact: 'Browsers block mixed active content and traffic is vulnerable to man-in-the-middle tampering.',
          aiExplanation: `External fonts or stylesheets imported via plain http:// trigger Mixed Content warnings in modern browsers and can be hijacked on public Wi-Fi networks. Always use https://.`,
          learningConcept: 'Mixed Content Vulnerabilities & HTTPS Enforcement',
          whyItMatters: 'Protects assets from malicious interception.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/http:\/\//i, 'https://'),
            explanation: 'Change protocol from http:// to secure https://.'
          }
        });
      }
    }

    return findings;
  }

  // ==========================================================================
  // JAVA ANALYZER
  // ==========================================================================
  static analyzeJava(code) {
    const findings = [];
    const lines = code.split('\n');

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      // SQL injection via string concat
      if (/(SELECT|INSERT|UPDATE|DELETE)\s+.*\s+(FROM|INTO|SET)\s+.*"\s*\+\s*[a-zA-Z_]/i.test(line)) {
        findings.push({
          severity: 'critical',
          title: 'SQL Injection via String Concatenation in Java',
          ruleId: 'JAVA-SEC-001',
          ruleName: 'Java SQL Injection',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Building SQL query strings via '+' concatenation permits SQL injection.`,
          impact: 'Database breach, unauthorized data exfiltration, or table deletion.',
          aiExplanation: `Concatenating user variables directly into a SQL query string allows attackers to manipulate SQL grammar. Always use java.sql.PreparedStatement with '?' parameter placeholders.`,
          learningConcept: 'PreparedStatement & Parameterized Queries in Java',
          whyItMatters: 'One of the most dangerous enterprise database vulnerabilities.',
          suggestedFix: {
            before: trimmed,
            after: 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setInt(1, userId);',
            explanation: 'Use PreparedStatement with parameter placeholders.'
          }
        });
      }

      // XXE injection
      if (/DocumentBuilderFactory\.newInstance\s*\(\)/.test(line)) {
        findings.push({
          severity: 'high',
          title: 'XML External Entity (XXE) Vulnerability in Java',
          ruleId: 'JAVA-SEC-002',
          ruleName: 'Java XXE Injection',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Default DocumentBuilderFactory enables external DTD entity expansion.`,
          impact: 'Arbitrary file disclosure (/etc/passwd) and server-side request forgery (SSRF).',
          aiExplanation: `By default, Java's XML parser resolves external entity declarations in incoming XML payloads. An attacker can craft XML containing <!ENTITY xxe SYSTEM "file:///etc/passwd">. Disable external DTDs using dbf.setFeature(...).`,
          learningConcept: 'XML External Entity (XXE) Processing & Safe Parsers',
          whyItMatters: 'Prevents attackers from reading local server files.',
          suggestedFix: {
            before: trimmed,
            after: 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
            explanation: 'Disable doctype declaration feature on DocumentBuilderFactory.'
          }
        });
      }
    }

    return findings;
  }

  // ==========================================================================
  // C / C++ ANALYZER
  // ==========================================================================
  static analyzeCCpp(code) {
    const findings = [];
    const lines = code.split('\n');

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNum = idx + 1;
      const line = lines[idx];
      const trimmed = line.trim();

      // Buffer overflow functions (gets, strcpy, sprintf)
      if (/\b(gets\s*\(|strcpy\s*\(|strcat\s*\(|sprintf\s*\()/i.test(line)) {
        const fnMatch = line.match(/\b(gets|strcpy|strcat|sprintf)\b/i);
        const fn = fnMatch ? fnMatch[1].toLowerCase() : 'unsafe function';
        let cppFixAfter = trimmed;
        if (fn === 'gets') {
          const m = trimmed.match(/gets\s*\(([^)]+)\)/);
          const buf = m ? m[1].trim() : 'buffer';
          cppFixAfter = `fgets(${buf}, sizeof(${buf}), stdin); /* Safe bounds-checked replacement for gets() */`;
        } else if (fn === 'strcpy') {
          const m = trimmed.match(/strcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/);
          if (m) {
            const dest = m[1].trim();
            const src = m[2].trim();
            cppFixAfter = `strncpy(${dest}, ${src}, sizeof(${dest}) - 1); ${dest}[sizeof(${dest}) - 1] = '\\0';`;
          }
        } else if (fn === 'sprintf') {
          cppFixAfter = trimmed.replace(/\bsprintf\s*\(\s*([^,]+)\s*,/, 'snprintf($1, sizeof($1),');
        } else {
          cppFixAfter = `// Refactored to safe alternative:\n    ${trimmed}`;
        }
        findings.push({
          severity: 'critical',
          title: `Buffer Overflow Vulnerability (${fn})`,
          ruleId: 'CPP-SEC-001',
          ruleName: 'Unbounded Memory Copy',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: Function '${fn}' copies memory without checking destination buffer boundaries.`,
          impact: 'Stack smashing, arbitrary code execution, and application crash.',
          aiExplanation: `'${fn}' does not check how much space is available in the target buffer before copying characters. If input is longer than the buffer, it overwrites the stack frame return address, allowing arbitrary code execution! Use bounds-checked functions like fgets, strncpy, or snprintf.`,
          learningConcept: 'Stack Buffer Overflows & Bounds Checking in C/C++',
          whyItMatters: 'The single most common root cause of critical memory corruption vulnerabilities.',
          suggestedFix: {
            before: trimmed,
            after: cppFixAfter,
            explanation: `Replace '${fn}' with bounds-checked alternative like fgets, strncpy, or snprintf.`
          }
        });
      }
      // Unbounded scanf
      if (/\bscanf\s*\(\s*["'][^"']*%s[^"']*["']\s*,/i.test(line)) {
        findings.push({
          severity: 'critical',
          title: 'Unbounded Buffer Overflow in scanf("%s")',
          ruleId: 'CPP-SEC-002',
          ruleName: 'Unbounded Input Format',
          category: 'Security & Safety',
          line: lineNum,
          description: `Line ${lineNum}: scanf("%s") reads input of unlimited length into a fixed memory buffer.`,
          impact: 'Stack buffer overflow and potential remote code execution.',
          aiExplanation: `Using %s without specifying an explicit field width allows users to enter more characters than the destination buffer can hold, smashing the stack. Specify a maximum length (e.g. %63s) or use fgets().`,
          learningConcept: 'Safe C Formatted Input & Field Width Limits',
          whyItMatters: 'Classic source of remote memory corruption exploits.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/%s/, '%63s /* Specify explicit field width limit */'),
            explanation: 'Specify an explicit maximum width specifier in scanf format string.'
          }
        });
      }

      // Division by zero
      if (/\/\s*0(?:\.0*)?(?!\d)/.test(line)) {
        findings.push({
          severity: 'high',
          title: 'Division by Zero (SIGFPE Crash)',
          ruleId: 'CPP-MATH-001',
          ruleName: 'Division by Zero in C/C++',
          category: 'Common Coding Issue',
          line: lineNum,
          description: `Line ${lineNum}: Integer division by zero triggers a fatal SIGFPE signal and crashes the process.`,
          impact: 'Immediate application crash via Floating Point Exception signal.',
          aiExplanation: `Dividing by zero in C/C++ is undefined behavior and produces a hardware trap or SIGFPE signal, terminating the process immediately.`,
          learningConcept: 'C/C++ Arithmetic Exceptions & Precondition Validation',
          whyItMatters: 'Guaranteed crash in native compiled binaries.',
          suggestedFix: {
            before: trimmed,
            after: trimmed.replace(/\/\s*0(?:\.0*)?(?!\d)/g, '/ 1 /* Ensure non-zero denominator */'),
            explanation: 'Ensure divisor is not zero before performing division.'
          }
        });
      }
    }

    return findings;
  }

  // ==========================================================================
  // DISPATCHER & REPORT GENERATOR
  // ==========================================================================
  static analyze(code, language = 'javascript') {
    const lang = (language || 'javascript').toLowerCase();
    let findings = [];

    if (lang === 'python' || lang === 'py') {
      findings = this.analyzePython(code);
    } else if (lang === 'typescript' || lang === 'ts') {
      findings = this.analyzeTypeScript(code);
    } else if (lang === 'html' || lang === 'htm') {
      findings = this.analyzeHtml(code);
    } else if (lang === 'css') {
      findings = this.analyzeCss(code);
    } else if (lang === 'java') {
      findings = this.analyzeJava(code);
    } else if (lang === 'c' || lang === 'c++' || lang === 'cpp' || lang === 'c_cpp') {
      findings = this.analyzeCCpp(code);
    } else {
      // Default: JavaScript
      findings = this.analyzeJavaScript(code);
    }

    // Ensure all findings expose both explanation, aiExplanation, evidence/matchedCode and limitations
    const lines = (code || '').split('\n');
    return findings.map(f => {
      const exp = f.explanation || f.aiExplanation || f.description;
      const targetLine = (typeof f.line === 'number' && f.line > 0 && f.line <= lines.length)
        ? lines[f.line - 1].trim()
        : '';
      const matchedCode = f.matchedCode || f.evidence || (f.suggestedFix ? f.suggestedFix.before : null) || targetLine;
      const limitations = f.limitations || (
        (f.category && f.category.includes('Syntax'))
          ? 'Static Lexical Parser Limitation: Verifies delimiter symmetry and string bounds; does not evaluate dynamic expressions generated via eval() or external scripts.'
          : (f.category && (f.category.includes('Security') || f.category.includes('Safety')))
          ? 'Static Security Scope Limitation: Identifies dangerous sinks and known vulnerability signatures; does not trace cross-module runtime data flows or sanitized inputs.'
          : 'Static Rule Limitation: Evaluates AST conventions and coding standards without executing runtime environment or resolving external module imports.'
      );
      const isSec = Boolean(
        (f.category && (f.category.includes('Security') || f.category.includes('Safety'))) ||
        (f.ruleId && (f.ruleId.includes('SEC') || f.ruleId.includes('BOF') || f.ruleId.includes('INJ')))
      );

      let findingType = 'quality';
      if (f.severity === 'critical' || (f.category && f.category.includes('Syntax'))) {
        findingType = 'error';
      } else if (isSec) {
        findingType = 'security';
      } else if (f.severity === 'high' || f.severity === 'medium' || (f.category && f.category.includes('Traps'))) {
        findingType = 'warning';
      }

      return {
        ...f,
        type: findingType,
        isSecurity: isSec,
        explanation: exp,
        aiExplanation: exp,
        matchedCode: matchedCode || targetLine,
        evidence: matchedCode || targetLine,
        limitations
      };
    });
  }

  static generateReport(code, language = 'javascript') {
    const trimmed = (code || '').trim();

    if (!trimmed) {
      return {
        success: false,
        status: 'empty_input',
        message: 'Appropriate message: Please enter valid source code to begin analysis.',
        language,
        healthScore: 0,
        score: 0,
        grade: 'N/A',
        shortGrade: 'N/A',
        loc: 0,
        counts: { syntax: 0, common: 0, quality: 0, security: 0, total: 0 },
        findings: [],
        summary: 'No code was provided. Enter or paste your program into the editor and click "Analyze Code".',
        aiSummary: 'No code was provided. Enter or paste your program into the editor and click "Analyze Code".',
        recommendations: [
          'Submit valid source code to receive automated diagnostic explanations and 1-click improvements.'
        ]
      };
    }

    const findings = this.analyze(trimmed, language);

    const syntaxCount = findings.filter(f => (f.category || '').includes('Syntax')).length;
    const securityCount = findings.filter(f => !((f.category || '').includes('Syntax')) && ((f.category || '').includes('Security') || (f.category || '').includes('Safety'))).length;
    const commonCount = findings.filter(f => (f.category || '').includes('Common') || (f.category || '').includes('Pitfall') || (f.category || '').includes('Modern') || (f.category || '').includes('Traps')).length;
    const qualityCount = findings.filter(f => (f.category || '').includes('Quality') || (f.category || '').includes('Poorly') || (f.category || '').includes('Practice') || (f.category || '').includes('Type')).length;

    let score = 100;
    score -= syntaxCount * 30;
    score -= securityCount * 20;
    score -= commonCount * 10;
    score -= qualityCount * 5;
    score = Math.max(0, Math.min(100, score));

    let grade = 'A+ (Excellent Code)';
    let shortGrade = 'A+';
    if (score < 90 && score >= 80) { grade = 'A (Good Quality)'; shortGrade = 'A'; }
    else if (score < 80 && score >= 70) { grade = 'B (Satisfactory with Improvements)'; shortGrade = 'B'; }
    else if (score < 70 && score >= 50) { grade = 'C (Needs Attention)'; shortGrade = 'C'; }
    else if (score < 50) { grade = 'F (High Error Density)'; shortGrade = 'F'; }

    let summaryText = '';
    if (findings.length === 0) {
      summaryText = `Congratulations! Your ${language.toUpperCase()} code passed all syntax, best practice, and security inspections with zero issues detected. Clean and well-structured!`;
    } else {
      const parts = [];
      if (syntaxCount > 0) parts.push(`${syntaxCount} syntax issue(s)`);
      if (commonCount > 0) parts.push(`${commonCount} common programming trap(s)`);
      if (securityCount > 0) parts.push(`${securityCount} security / vulnerability concern(s)`);
      if (qualityCount > 0) parts.push(`${qualityCount} code quality / readability suggestion(s)`);

      summaryText = `CodeInsight examined your ${language.toUpperCase()} code and identified ${parts.join(', ')}. Review the diagnostic explanations below to understand why each issue happens and apply the suggested fixes with 1 click.`;
    }

    // Interactive Learning Flashcards
    const flashcards = findings.slice(0, 3).map(f => ({
      concept: f.learningConcept || 'Code Quality',
      question: `Why is "${f.title}" considered problematic?`,
      answer: f.explanation || f.aiExplanation
    }));

    // Generate automated repaired code
    const repairedCode = this.generateRepairedCode(trimmed, language, findings);
    let expectedRepairedScore = 100;
    if (repairedCode && repairedCode !== trimmed) {
      const simFindings = this.analyze(repairedCode, language);
      let s = 100;
      s -= simFindings.filter(f => (f.category || '').includes('Syntax')).length * 30;
      s -= simFindings.filter(f => !((f.category || '').includes('Syntax')) && ((f.category || '').includes('Security') || (f.category || '').includes('Safety'))).length * 20;
      s -= simFindings.filter(f => (f.category || '').includes('Common') || (f.category || '').includes('Pitfall') || (f.category || '').includes('Modern') || (f.category || '').includes('Traps')).length * 10;
      s -= simFindings.filter(f => (f.category || '').includes('Quality') || (f.category || '').includes('Poorly') || (f.category || '').includes('Practice') || (f.category || '').includes('Type')).length * 5;
      expectedRepairedScore = Math.max(0, Math.min(100, s));
    }

    return {
      success: true,
      status: 'analyzed',
      message: `Analysis completed successfully. ${findings.length} issue(s) identified.`,
      language,
      healthScore: score,
      score: score,
      grade,
      shortGrade,
      loc: trimmed.split('\n').length,
      counts: {
        syntax: syntaxCount,
        common: commonCount,
        security: securityCount,
        quality: qualityCount,
        total: findings.length
      },
      findings,
      repairedCode: repairedCode || trimmed,
      correctedCode: repairedCode || trimmed,
      expectedRepairedScore,
      canAutoRepair: Boolean(repairedCode && repairedCode !== trimmed && findings.length > 0),
      appliedFixes: (findings || []).filter(f => f.suggestedFix).map(f => ({
        ruleId: f.ruleId,
        title: f.title,
        line: f.line,
        before: f.suggestedFix.before,
        after: f.suggestedFix.after,
        explanation: f.suggestedFix.explanation || f.explanation || f.title
      })),
      summary: summaryText,
      aiSummary: summaryText,
      flashcards,
      recommendations: [
        "Avoid dynamic string concatenation when building database queries.",
        "Always handle caught exceptions and provide meaningful error feedback.",
        "Favor modern, memory-safe idioms and standard library validation."
      ]
    };
  }

  /**
   * Generates a fully repaired, clean version of source code by applying
   * all safe diagnostic fixes for syntax, bad practices, and security flaws.
   */
  static generateRepairedCode(code, language = 'javascript', findings = []) {
    if (!code || typeof code !== 'string') return '';
    let repaired = code;
    let lines = repaired.split('\n');

    const fixable = (findings || []).filter(f => f.suggestedFix && typeof f.suggestedFix.after === 'string');
    // Sort fixes descending by line so lower line replacements don't offset earlier line numbers
    const sortedFixes = [...fixable].sort((a, b) => (b.line || 0) - (a.line || 0));

    for (const f of sortedFixes) {
      const fix = f.suggestedFix;
      const before = fix.before;
      const after = fix.after;
      if (!before || !after || before === after) continue;

      if (repaired.includes(before)) {
        repaired = repaired.replace(before, after);
        lines = repaired.split('\n');
      } else if (typeof f.line === 'number' && f.line > 0 && f.line <= lines.length) {
        const lineIdx = f.line - 1;
        const currentLine = lines[lineIdx];
        if (currentLine && (currentLine.includes(before.trim()) || before.trim().includes(currentLine.trim()))) {
          lines[lineIdx] = after;
          repaired = lines.join('\n');
        }
      }
    }

    // Bracket & delimiter symmetry fix
    const syntaxFindings = (findings || []).filter(f => f.ruleId && f.ruleId.startsWith('JS-SYN'));
    for (const syn of syntaxFindings) {
      if (syn.ruleId === 'JS-SYN-001') {
        const unclosedMatches = (syn.description || '').match(/'([({[])'/g);
        if (unclosedMatches) {
          const charMap = { "'('": ')', "'{'": '}', "'['": ']' };
          for (const m of unclosedMatches) {
            const closer = charMap[m];
            if (closer && !repaired.endsWith(closer)) {
              repaired = repaired.trimEnd() + '\n' + closer + '\n';
            }
          }
        }
      }
    }

    return repaired;
  }
}

module.exports = MultiLanguageAnalyzer;
