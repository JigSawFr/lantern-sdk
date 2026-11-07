// A copy button on every code block of the pages that load it (the specification, the quick start): the
// block's text goes to the clipboard, and the block's language, when it names one, is shown beside the button.
// The texts are the page's catalog's (data-* attributes of this script's tag). Without script the blocks are
// as they were.
'use strict';

(function () {
  const me = document.currentScript;
  if (!me) return;
  const T = me.dataset;
  const blocks = [...document.querySelectorAll('main pre, .prose pre')].filter((p, i, all) => all.indexOf(p) === i);
  if (!blocks.length) return;

  const live = document.createElement('p');
  live.className = 'sr'; live.setAttribute('role', 'status'); live.setAttribute('aria-live', 'polite');
  document.body.appendChild(live);
  const say = (text) => { live.textContent = ''; setTimeout(() => { live.textContent = text; }, 30); };

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise((ok, fail) => {
      const field = document.createElement('textarea');
      field.value = text; field.setAttribute('readonly', ''); field.className = 'sr';
      document.body.appendChild(field); field.select();
      let done = false;
      try { done = document.execCommand('copy'); } catch (e) { done = false; }
      field.remove();
      done ? ok() : fail(new Error('copy'));
    });
  }

  const ns = 'http://www.w3.org/2000/svg';
  const icon = (paths, cls) => {
    const el = document.createElementNS(ns, 'svg');
    el.setAttribute('viewBox', '0 0 24 24'); el.setAttribute('aria-hidden', 'true'); el.setAttribute('class', cls);
    for (const d of paths) { const p = document.createElementNS(ns, 'path'); p.setAttribute('d', d); el.appendChild(p); }
    return el;
  };

  for (const pre of blocks) {
    const code = pre.querySelector('code');
    const named = code && /(?:^|\s)language-([\w-]+)/.exec(code.className);
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    pre.replaceWith(wrap);
    const bar = document.createElement('div');
    bar.className = 'code-bar';
    const label = document.createElement('span');
    label.className = 'code-lang'; label.setAttribute('aria-hidden', 'true');
    label.textContent = named ? named[1] : '';
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'code-copy';
    button.setAttribute('aria-label', T.copy + (named ? ' (' + named[1] + ')' : ''));
    button.append(icon(['M9 9h11v11H9z', 'M5 15V5a1 1 0 0 1 1-1h10'], 'i-copy'), icon(['M5 12.5l4.5 4.5L19 7.5'], 'i-done'));
    const text = document.createElement('span');
    text.className = 'code-text'; text.textContent = T.copy;
    button.append(text);
    button.addEventListener('click', () => {
      copy((code || pre).textContent.replace(/\n$/, '')).then(() => {
        // Umami counts that a block was copied, never what it held (the privacy text on boreale.dev)
        try { if (window.umami && typeof window.umami.track === 'function') window.umami.track('copy'); } catch (e) { /* counting never breaks the page */ }
        button.dataset.done = ''; text.textContent = T.copied;
        setTimeout(() => { button.removeAttribute('data-done'); text.textContent = T.copy; }, 1600);
        say(T.copied);
      }, () => say(T.failed));
    });
    bar.append(label, button);
    wrap.append(bar, pre);
  }
})();
