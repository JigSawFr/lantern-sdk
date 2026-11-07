// "Run it, here" on the SDK's page: the button loads the page's playground (assets/sdk-playground.js: the SDK's own
// TypeScript client and server, built by tools/build_playground.mjs) the first time it is pressed, runs its four calls
// against a made-up library in this page, and shows each call, what went over the in-page connection and what came
// back. Nothing leaves the page. Without script the section stays hidden.
'use strict';

(function () {
  const root = document.getElementById('try');
  if (!root) return;
  const T = root.dataset;
  const button = root.querySelector('.try-run');
  const out = root.querySelector('.try-out');
  const base = (document.currentScript && document.currentScript.src) || document.querySelector('script[src*="playground.js"]').src;
  const bundle = new URL('sdk-playground.js', base).href;

  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  let loading;
  const load = () => loading || (loading = new Promise((ok, fail) => {
    const script = document.createElement('script');
    script.src = bundle;
    script.onload = () => ok(window.lanternPlayground);
    script.onerror = () => { loading = undefined; fail(new Error('load')); };
    document.head.append(script);
  }));

  function show(steps) {
    out.replaceChildren();
    steps.forEach((step, i) => {
      const card = el('article', 'try-step');
      card.append(el('h3', null, `${i + 1}. ${T['s' + (i + 1)]}`));
      const code = el('pre'); code.tabIndex = 0;
      code.append(el('code', 'language-ts', step.code));
      card.append(code);
      card.append(el('h4', null, T.requests));
      const list = el('ul', 'try-wire');
      for (const r of step.requests) {
        const item = el('li');
        item.append(el('code', null, `${r.method} ${r.path}`), el('span', r.status < 400 ? 'try-ok' : 'try-bad', String(r.status)));
        list.append(item);
      }
      card.append(list);
      card.append(el('h4', null, T.result));
      const result = el('pre'); result.tabIndex = 0;
      result.append(el('code', 'language-json', JSON.stringify(step.result, null, 2)));
      card.append(result);
      out.append(card);
    });
  }

  let ran = false;
  button.textContent = T.run;
  button.addEventListener('click', async () => {
    button.disabled = true; button.textContent = T.running;
    try {
      const playground = await load();
      show(await playground.run());
      ran = true;
    } catch (e) {
      out.replaceChildren(el('p', 'note', T.error));
    } finally {
      button.disabled = false; button.textContent = ran ? T.again : T.run;
    }
  });
  root.hidden = false;
})();
