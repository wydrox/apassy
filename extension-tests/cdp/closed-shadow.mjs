// CDP can inspect a closed root for tests; page JavaScript cannot.
export async function shadowNodes(cdp, attribute) {
  await cdp.send("DOM.enable");
  const { root } = await cdp.send("DOM.getDocument", { depth: -1, pierce: true });
  const found = [];
  function walk(node, inside = false) {
    inside ||= (node.attributes || []).includes(attribute);
    if (inside) found.push(node);
    for (const child of [...(node.children || []), ...(node.shadowRoots || [])]) walk(child, inside);
  }
  walk(root); return found;
}
export async function shadowText(cdp, attribute) {
  return (await shadowNodes(cdp, attribute)).filter((n) => n.nodeType === 3 && !n.nodeValue.startsWith(":host")).map((n) => n.nodeValue).join(" ");
}
export async function shadowButton(cdp, attribute, label) {
  // Save offers require a visibly stable surface before pointer/key activation.
  if (attribute === "data-apassy-save-offer") await new Promise((r) => setTimeout(r, 500));
  const nodes = await shadowNodes(cdp, attribute);
  const button = nodes.find((n) => n.nodeName === "BUTTON" && n.children?.some((c) => c.nodeType === 3 && c.nodeValue === label));
  if (!button) throw new Error(`Missing ${label} in ${attribute}`);
  const { model } = await cdp.send("DOM.getBoxModel", { nodeId: button.nodeId });
  const q = model.content, x = (q[0] + q[2] + q[4] + q[6]) / 4, y = (q[1] + q[3] + q[5] + q[7]) / 4;
  for (const type of ["mousePressed", "mouseReleased"]) await cdp.send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
}
