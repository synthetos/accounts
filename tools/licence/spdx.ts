/**
 * A strict, dependency-free evaluator for SPDX licence expressions
 * (https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/):
 * identifiers, `AND`, `OR`, `WITH` and parentheses.
 *
 * Fails closed: anything it cannot parse is "not allowed".
 */

type Expr =
  | { readonly kind: 'id'; readonly id: string }
  | { readonly kind: 'and' | 'or'; readonly left: Expr; readonly right: Expr };

const IDENTIFIER = /^[A-Za-z0-9.+:-]+$/;

function tokenize(text: string): string[] | undefined {
  const tokens = text.match(/\(|\)|[^\s()]+/g) ?? [];
  return tokens.every((t) => t === '(' || t === ')' || IDENTIFIER.test(t)) ? tokens : undefined;
}

function parse(tokens: readonly string[]): Expr | undefined {
  let pos = 0;
  const peek = (): string | undefined => tokens[pos];

  const atom = (): Expr | undefined => {
    const token = peek();
    if (token === undefined || token === ')' || isOperator(token)) return undefined;
    pos += 1;
    if (token === '(') {
      const inner = or();
      if (inner === undefined || peek() !== ')') return undefined;
      pos += 1;
      return inner;
    }
    if (peek() === 'WITH') {
      pos += 1;
      const exception = peek();
      if (exception === undefined || exception === '(' || exception === ')' || isOperator(exception)) return undefined;
      pos += 1;
      // A licence with an exception is its own identifier for policy
      // purposes: it is allowed only if listed verbatim.
      return { kind: 'id', id: `${token} WITH ${exception}` };
    }
    return { kind: 'id', id: token };
  };

  const and = (): Expr | undefined => {
    let left = atom();
    while (left !== undefined && peek() === 'AND') {
      pos += 1;
      const right = atom();
      if (right === undefined) return undefined;
      left = { kind: 'and', left, right };
    }
    return left;
  };

  const or = (): Expr | undefined => {
    let left = and();
    while (left !== undefined && peek() === 'OR') {
      pos += 1;
      const right = and();
      if (right === undefined) return undefined;
      left = { kind: 'or', left, right };
    }
    return left;
  };

  const result = or();
  return result !== undefined && pos === tokens.length ? result : undefined;
}

function isOperator(token: string): boolean {
  return token === 'AND' || token === 'OR' || token === 'WITH';
}

function satisfied(expr: Expr, allowed: ReadonlySet<string>): boolean {
  switch (expr.kind) {
    case 'id':
      return allowed.has(expr.id);
    case 'and':
      return satisfied(expr.left, allowed) && satisfied(expr.right, allowed);
    case 'or':
      return satisfied(expr.left, allowed) || satisfied(expr.right, allowed);
  }
}

function collectIds(expr: Expr, out: string[]): string[] {
  if (expr.kind === 'id') out.push(expr.id);
  else {
    collectIds(expr.left, out);
    collectIds(expr.right, out);
  }
  return out;
}

/**
 * True if the expression can be satisfied using only `allowed` licences:
 * every operand of an `AND`, and at least one operand of an `OR`.
 * An empty or unparseable expression is never satisfied.
 */
export function isSatisfiedBy(expression: string, allowed: ReadonlySet<string>): boolean {
  const tokens = tokenize(expression);
  if (tokens === undefined || tokens.length === 0) return false;
  const expr = parse(tokens);
  return expr !== undefined && satisfied(expr, allowed);
}

/**
 * Every licence identifier named in the expression (with `WITH` exceptions
 * kept attached), or `undefined` if the expression does not parse.
 */
export function licenceIds(expression: string): string[] | undefined {
  const tokens = tokenize(expression);
  if (tokens === undefined || tokens.length === 0) return undefined;
  const expr = parse(tokens);
  return expr === undefined ? undefined : collectIds(expr, []);
}
