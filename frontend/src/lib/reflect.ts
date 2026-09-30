/**
 * Reflected-parameter finder — the passive half of hunting XSS.
 *
 * It takes the inputs a request carried and reports which of their values came back in
 * the response, and where: in HTML text, inside an attribute, or inside a script. That
 * "where" is the whole point — a value reflected into a script context is a different
 * lead from one reflected into visible text — but reflection is not execution, so each
 * hit is a place to test, never a confirmed XSS.
 */

export type ReflectionContext = "script" | "attribute" | "html" | "url";

export interface RequestInput {
  source: string;
  name: string;
  value: string;
}

export interface Reflection {
  name: string;
  value: string;
  source: string;
  count: number;
  contexts: ReflectionContext[];
}

/** Pull the input values a request carried: query keys, and form or JSON body values. */
export function extractInputs(requestHead: string, requestBody: string): RequestInput[] {
  const inputs: RequestInput[] = [];

  const firstLine = requestHead.split(/\r?\n/)[0] ?? "";
  const target = firstLine.split(/\s+/)[1] ?? "";
  const q = target.indexOf("?");
  if (q >= 0) {
    for (const pair of target.slice(q + 1).split("&")) {
      const [k, v = ""] = pair.split("=");
      if (k) inputs.push({ source: "query", name: safeDecode(k), value: safeDecode(v) });
    }
  }

  const body = requestBody.trim();
  if (body.startsWith("{") || body.startsWith("[")) {
    try {
      walkJson(JSON.parse(body), "", inputs);
    } catch {
      /* not JSON after all */
    }
  } else if (/^[^=&\s]+=/.test(body)) {
    for (const pair of body.split("&")) {
      const [k, v = ""] = pair.split("=");
      if (k) inputs.push({ source: "body", name: safeDecode(k), value: safeDecode(v) });
    }
  }
  return inputs;
}

function walkJson(value: unknown, path: string, out: RequestInput[]) {
  if (value === null) return;
  if (typeof value === "object") {
    if (Array.isArray(value)) value.forEach((v, i) => walkJson(v, `${path}[${i}]`, out));
    else for (const [k, v] of Object.entries(value)) walkJson(v, path ? `${path}.${k}` : k, out);
    return;
  }
  out.push({ source: "json", name: path, value: String(value) });
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

/** Find which input values are reflected in the response, and in what context. */
export function findReflections(inputs: RequestInput[], response: string): Reflection[] {
  const byValue = new Map<string, Reflection>();

  for (const input of inputs) {
    const v = input.value;
    // Short or empty values reflect by coincidence; skip them.
    if (v.length < 3) continue;
    if (byValue.has(v)) continue;

    const contexts = new Set<ReflectionContext>();
    let count = 0;
    let from = 0;
    for (;;) {
      const idx = response.indexOf(v, from);
      if (idx < 0) break;
      count++;
      contexts.add(contextAt(response, idx));
      from = idx + v.length;
      if (count > 50) break;
    }
    if (count > 0) {
      byValue.set(v, {
        name: input.name,
        value: v,
        source: input.source,
        count,
        contexts: [...contexts],
      });
    }
  }

  return [...byValue.values()].sort((a, b) => b.count - a.count);
}

/** Classify where in the response a reflection landed, from the text around it. */
function contextAt(response: string, index: number): ReflectionContext {
  const before = response.slice(Math.max(0, index - 400), index);

  // Inside a <script> block if the last script tag before us is unclosed.
  const lastOpen = before.lastIndexOf("<script");
  const lastClose = before.lastIndexOf("</script");
  if (lastOpen > lastClose) return "script";

  // Inside an attribute value if we are past an unbalanced opening quote within a tag.
  const lastTagOpen = before.lastIndexOf("<");
  const lastTagClose = before.lastIndexOf(">");
  if (lastTagOpen > lastTagClose) {
    const attrPart = before.slice(lastTagOpen);
    const quotes = (attrPart.match(/["']/g) ?? []).length;
    if (quotes % 2 === 1) return "attribute";
  }

  // A reflection inside a URL/href is worth separating from plain text.
  if (/https?:\/\/[^\s"'<>]*$/.test(before)) return "url";

  return "html";
}
