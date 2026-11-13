/** Split SQL without breaking quoted newlines/semicolons or trigger BEGIN/CASE bodies.
 * Used by both the scheduled scratch restore and the protected CI restore path. */
export function splitSql(sql: string): string[] {
  const out: string[] = [];
  let start = 0, quote = '', depth = 0, trigger = false, word = '', prefix = '';
  const token = (): void => {
    if (!word) return;
    const upper = word.toUpperCase();
    prefix += `${upper} `;
    if (/^CREATE (?:TEMP(?:ORARY)? )?TRIGGER /.test(prefix)) trigger = true;
    if (trigger && (upper === 'BEGIN' || upper === 'CASE')) depth++;
    if (trigger && upper === 'END') depth--;
    word = '';
  };
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i]!;
    if (quote) {
      if (c === quote) { if (quote !== ']' && sql[i + 1] === quote) i++; else quote = ''; }
      continue;
    }
    if (c === '-' && sql[i + 1] === '-') { token(); const end = sql.indexOf('\n', i); i = end < 0 ? sql.length : end; continue; }
    if (c === '/' && sql[i + 1] === '*') { token(); const end = sql.indexOf('*/', i + 2); if (end < 0) throw new Error('Unclosed SQL comment'); i = end + 1; continue; }
    if (/[a-z0-9_]/i.test(c)) { word += c; continue; }
    token();
    if (c === "'" || c === '"' || c === '`' || c === '[') { quote = c === '[' ? ']' : c; continue; }
    if (c === ';' && depth === 0) {
      const statement = sql.slice(start, i).trim();
      if (statement) out.push(statement);
      start = i + 1; trigger = false; prefix = '';
    }
  }
  token();
  if (quote || depth !== 0) throw new Error('Incomplete SQL statement');
  const tail = sql.slice(start).trim();
  if (tail && !/^(?:--[^\n]*(?:\n|$)\s*)+$/.test(tail)) out.push(tail);
  if (!out.length) throw new Error('Empty SQL dump');
  return out;
}
