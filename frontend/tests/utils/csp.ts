export type CspDirectiveMap = Map<string, string[]>;

export function parseCspDirectives(headerValue: string): CspDirectiveMap {
  const directives = new Map<string, string[]>();
  headerValue
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .forEach((directive) => {
      const tokens = directive.split(/\s+/).filter(Boolean);
      if (!tokens.length) {
        return;
      }
      const name = tokens[0].toLowerCase();
      const values = tokens.slice(1);
      directives.set(name, values);
    });
  return directives;
}

export function getDirectiveValues(map: CspDirectiveMap, name: string): string[] | undefined {
  return map.get(name.toLowerCase());
}

export function directiveIncludes(
  map: CspDirectiveMap,
  name: string,
  expected: string,
): boolean {
  const values = getDirectiveValues(map, name);
  if (!values || !values.length) {
    return false;
  }
  return values.some((value) => value.includes(expected));
}
