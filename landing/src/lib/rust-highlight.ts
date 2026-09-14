/*
  A very small Rust highlighter, run at build time.

  Shiki would do this properly and Astro already bundles it, but it emits its
  own theme's colours as inline styles, and this page's snippets have to take
  their colours from the design tokens — otherwise the code block is the one
  place on the site that ignores the palette. The snippets here are also
  fixed, short, and written by us, so a full grammar is not buying anything a
  handful of patterns cannot.

  This is therefore deliberately *not* a general Rust parser. It handles the
  constructs that appear in the snippets on this page and would mis-highlight
  plenty of real-world Rust — raw strings, nested generics in odd positions,
  lifetimes. If a snippet ever needs something this cannot colour, reach for
  Shiki with a token-to-CSS-variable mapping rather than growing this.
*/

const KEYWORDS = new Set([
  'as', 'async', 'await', 'const', 'crate', 'dyn', 'else', 'enum', 'fn', 'for',
  'if', 'impl', 'in', 'let', 'match', 'mod', 'move', 'mut', 'pub', 'ref',
  'return', 'self', 'static', 'struct', 'trait', 'type', 'use', 'where',
  'while', 'true', 'false',
]);

/*
  Order matters: the first alternative that matches at a position wins, so
  comments and strings come before anything that could match inside them.
*/
const TOKEN = new RegExp(
  [
    '(?<comment>//[^\\n]*)',
    '(?<string>"(?:[^"\\\\\\n]|\\\\.)*")',
    '(?<attr>#!?\\[[^\\]\\n]*\\])',
    '(?<macro>\\b[a-z_][a-z0-9_]*!)',
    '(?<number>\\b\\d[\\d_]*(?:\\.\\d+)?\\b)',
    '(?<fn>\\b[a-z_][a-z0-9_]*(?=\\())',
    '(?<type>\\b[A-Z][A-Za-z0-9_]*\\b)',
    '(?<word>\\b[a-z_][a-z0-9_]*\\b)',
  ].join('|'),
  'g',
);

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
};

/** Escape before wrapping, never after — otherwise the spans get escaped too. */
function escapeHtml(text: string): string {
  return text.replace(/[&<>"]/g, (c) => ESCAPES[c]);
}

function wrap(cls: string, text: string): string {
  return `<span class="t-${cls}">${escapeHtml(text)}</span>`;
}

/**
 * Turn one line of Rust into HTML. Returns escaped markup, safe to drop into
 * `set:html`.
 */
export function highlightRustLine(line: string): string {
  let out = '';
  let last = 0;

  for (const match of line.matchAll(TOKEN)) {
    const groups = match.groups ?? {};
    const index = match.index ?? 0;

    // Anything between tokens — punctuation, whitespace, operators.
    if (index > last) out += escapeHtml(line.slice(last, index));
    last = index + match[0].length;

    if (groups.comment) out += wrap('comment', groups.comment);
    else if (groups.string) out += wrap('literal', groups.string);
    else if (groups.attr) out += wrap('comment', groups.attr);
    else if (groups.macro) out += wrap('macro', groups.macro);
    else if (groups.number) out += wrap('literal', groups.number);
    else if (groups.fn) out += wrap('fn', groups.fn);
    else if (groups.type) out += wrap('type', groups.type);
    else if (groups.word) {
      // A bare word is only a keyword if it is one; otherwise it is a binding
      // or a field and stays plain.
      out += KEYWORDS.has(groups.word) ? wrap('keyword', groups.word) : escapeHtml(groups.word);
    }
  }

  out += escapeHtml(line.slice(last));
  return out;
}

/** Split a snippet into already-highlighted lines, preserving blank ones. */
export function highlightRust(source: string): string[] {
  return source.replace(/\n$/, '').split('\n').map(highlightRustLine);
}
