'use strict';

const parser = require('@babel/parser');
const traverseModule = require('@babel/traverse');
const traverse = traverseModule.default || traverseModule;

const JS_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

function isJsFile(ext) {
  if (!ext) return false;
  const normalized = ext.startsWith('.') ? ext.toLowerCase() : `.${ext.toLowerCase()}`;
  return JS_EXTENSIONS.has(normalized);
}

/**
 * Unwrap ParenthesizedExpression, TypeCast, TSAsExpression, etc.
 */
function unwrap(node) {
  let cur = node;
  while (cur) {
    if (cur.type === 'ParenthesizedExpression') {
      cur = cur.expression;
    } else if (cur.type === 'TSAsExpression' || cur.type === 'TSTypeAssertion' || cur.type === 'TSNonNullExpression') {
      cur = cur.expression;
    } else {
      break;
    }
  }
  return cur;
}

function isMember(node) {
  const u = unwrap(node);
  return !!u && (u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression');
}

function memberProp(node) {
  const u = unwrap(node);
  if (!isMember(u)) return null;
  if (u.computed) {
    if (u.property.type === 'StringLiteral') return u.property.value;
    if (u.property.type === 'NumericLiteral') return String(u.property.value);
    return null;
  }
  return u.property.name || null;
}

/**
 * Turns an AST expression into a dotted name: e.g. "req.body.name", "crypto.createHash"
 */
function dotted(node) {
  const u = unwrap(node);
  if (!u) return null;
  if (u.type === 'Identifier') return u.name;
  if (u.type === 'ThisExpression') return 'this';
  if (isMember(u)) {
    const obj = dotted(u.object);
    const prop = memberProp(u);
    if (obj && prop) return `${obj}.${prop}`;
  }
  return null;
}

function isStaticString(node) {
  const u = unwrap(node);
  if (!u) return false;
  if (u.type === 'StringLiteral') return true;
  if (u.type === 'TemplateLiteral') return u.expressions.length === 0;
  return false;
}

function staticStringValue(node) {
  const u = unwrap(node);
  if (!u) return null;
  if (u.type === 'StringLiteral') return u.value;
  if (u.type === 'TemplateLiteral' && u.expressions.length === 0 && u.quasis[0]) {
    return u.quasis[0].value.cooked;
  }
  return null;
}

/**
 * Collect literal string fragments from template literal or binary + chain
 */
function literalFragments(node) {
  const u = unwrap(node);
  if (!u) return '';
  if (u.type === 'StringLiteral') return u.value;
  if (u.type === 'TemplateLiteral') {
    return u.quasis.map((q) => q.value.cooked || '').join(' ');
  }
  if (u.type === 'BinaryExpression' && u.operator === '+') {
    return `${literalFragments(u.left)} ${literalFragments(u.right)}`;
  }
  return '';
}

function isDynamicString(node) {
  const u = unwrap(node);
  if (!u) return false;
  if (u.type === 'TemplateLiteral') return u.expressions.length > 0;
  if (u.type === 'BinaryExpression' && u.operator === '+') {
    return !isStaticString(u.left) || !isStaticString(u.right);
  }
  return false;
}

function isUnboundGlobal(scope, name) {
  if (!scope || !name) return true;
  return !scope.getBinding(name);
}

/**
 * Resolves imported module and exported function name for a callee
 * E.g. const { exec } = require('child_process'); exec(...) -> { module: 'child_process', name: 'exec' }
 * E.g. const cp = require('child_process'); cp.exec(...) -> { module: 'child_process', name: 'exec' }
 */
function callTarget(scope, callee) {
  const u = unwrap(callee);
  if (!u) return null;

  // Pattern: obj.func()
  if (isMember(u)) {
    const objName = dotted(u.object);
    const prop = memberProp(u);
    if (!objName || !prop) return null;

    // Check if objName is a required/imported module
    const binding = scope && scope.getBinding(objName.split('.')[0]);
    if (binding && binding.path) {
      const init = binding.path.node.init;
      if (init && init.type === 'CallExpression' && init.callee.name === 'require' && init.arguments[0]) {
        const mod = staticStringValue(init.arguments[0]);
        if (mod) return { module: mod, name: prop };
      }
      if (binding.path.node.type === 'ImportDeclaration') {
        const mod = binding.path.node.source.value;
        if (mod) return { module: mod, name: prop };
      }
    }

    // Direct global modules like crypto, fs, path, child_process
    const directModules = new Set(['crypto', 'fs', 'path', 'child_process', 'http', 'https', 'axios', 'lodash', 'vm']);
    if (directModules.has(objName)) {
      return { module: objName, name: prop };
    }

    return null;
  }

  // Pattern: func() where func was destructured from require
  if (u.type === 'Identifier') {
    const binding = scope && scope.getBinding(u.name);
    if (binding && binding.path) {
      const parent = binding.path.parent;
      if (parent && parent.type === 'VariableDeclarator' && parent.init) {
        const init = parent.init;
        if (init.type === 'CallExpression' && init.callee.name === 'require' && init.arguments[0]) {
          const mod = staticStringValue(init.arguments[0]);
          return { module: mod, name: u.name };
        }
      }
      if (binding.path.node && binding.path.node.type === 'ImportSpecifier') {
        const decl = binding.path.parentPath && binding.path.parentPath.node;
        if (decl && decl.source) {
          const importedName = binding.path.node.imported ? binding.path.node.imported.name : u.name;
          return { module: decl.source.value, name: importedName };
        }
      }
    }
  }

  return null;
}

/**
 * Parse JS/TS source code safely into Babel AST
 */
function parseAst(source, filename = 'code.js') {
  try {
    return parser.parse(source, {
      sourceType: 'unambiguous',
      plugins: [
        'jsx',
        'typescript',
        'dynamicImport',
        'classProperties',
        'classPrivateProperties',
        'classPrivateMethods',
        'objectRestSpread',
        'optionalChaining',
        'nullishCoalescingOperator',
        'topLevelAwait',
        'decorators-legacy',
      ],
      tokens: false,
    });
  } catch {
    return null;
  }
}

/**
 * Lightweight AST Taint Analysis Engine
 * Tracks data flowing from HTTP request / client input sources to sensitive sinks
 */
function createTaintAnalysis(ast, source, options = {}) {
  const {
    server = true,
    client = false,
    serverSources = [
      'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
      'request.body', 'request.query', 'request.params',
      'ctx.request.body', 'ctx.query', 'event.body', 'event.queryStringParameters',
    ],
    clientSources = [
      'window.location', 'document.location', 'location.search', 'location.hash',
      'location.href', 'document.URL', 'document.referrer', 'window.name',
    ],
  } = options;

  const taintedBindings = new Set();
  const taintedExprs = new WeakSet();

  const isSourceDotted = (str) => {
    if (!str) return false;
    if (server) {
      for (const s of serverSources) {
        if (str === s || str.startsWith(`${s}.`)) return true;
      }
    }
    if (client) {
      for (const s of clientSources) {
        if (str === s || str.startsWith(`${s}.`)) return true;
      }
    }
    return false;
  };

  // Pre-pass: Traverse AST and register tainted variable bindings
  if (ast) {
    traverse(ast, {
      VariableDeclarator(path) {
        const { id, init } = path.node;
        if (!init) return;

        // Check if init is directly a source
        const d = dotted(init);
        const initTainted = isSourceDotted(d) || (d && taintedBindings.has(d.split('.')[0]));

        if (initTainted) {
          if (id.type === 'Identifier') {
            taintedBindings.add(id.name);
          } else if (id.type === 'ObjectPattern') {
            for (const prop of id.properties) {
              if (prop.type === 'ObjectProperty' && prop.value.type === 'Identifier') {
                taintedBindings.add(prop.value.name);
              } else if (prop.type === 'RestElement' && prop.argument.type === 'Identifier') {
                taintedBindings.add(prop.argument.name);
              }
            }
          }
        }
      },

      AssignmentExpression(path) {
        const { left, right } = path.node;
        const dRight = dotted(right);
        if (isSourceDotted(dRight) || (dRight && taintedBindings.has(dRight.split('.')[0]))) {
          const dLeft = dotted(left);
          if (dLeft) {
            taintedBindings.add(dLeft.split('.')[0]);
          }
        }
      },
    });
  }

  function isTainted(node, scope) {
    const u = unwrap(node);
    if (!u) return false;
    if (taintedExprs.has(u)) return true;

    // Check direct dotted representation
    const d = dotted(u);
    if (isSourceDotted(d)) return true;

    // Check identifier or member root
    if (u.type === 'Identifier' && taintedBindings.has(u.name)) {
      return true;
    }
    if (isMember(u)) {
      const root = d ? d.split('.')[0] : null;
      if (root && taintedBindings.has(root)) return true;
      if (isTainted(u.object, scope)) return true;
    }

    // Binary expressions (concatenations like 'SELECT * FROM ' + userInput)
    if (u.type === 'BinaryExpression' && u.operator === '+') {
      return isTainted(u.left, scope) || isTainted(u.right, scope);
    }

    // Template literals with expressions (`SELECT * FROM ${userInput}`)
    if (u.type === 'TemplateLiteral') {
      return u.expressions.some((expr) => isTainted(expr, scope));
    }

    // Calls that return input unchanged (e.g., String(userInput), decodeURIComponent(x))
    if (u.type === 'CallExpression') {
      const calleeName = dotted(u.callee);
      if (['String', 'decodeURI', 'decodeURIComponent', 'unescape', 'trim'].includes(calleeName) && u.arguments[0]) {
        return isTainted(u.arguments[0], scope);
      }
    }

    return false;
  }

  return {
    isTainted,
    taintedBindings,
  };
}

module.exports = {
  traverse,
  parseAst,
  isJsFile,
  unwrap,
  isMember,
  memberProp,
  dotted,
  isStaticString,
  staticStringValue,
  literalFragments,
  isDynamicString,
  callTarget,
  isUnboundGlobal,
  createTaintAnalysis,
};
