// The SDK page: the language chosen in an example's tabs is kept (in this browser only) and followed by the other
// examples and by the tables, whose column of that language is tinted. The picker (hidden until here) sets it too, and
// ?lang=python in the address chooses it. Without script the tabs and tables work as they are.
'use strict';

(function () {
  const KEY = 'lantern-sdk-language';
  const main = document.querySelector('main');
  if (!main) return;
  let stored = '';
  try { stored = localStorage.getItem(KEY) || ''; } catch (e) { stored = ''; }

  const buttons = main.querySelectorAll('.picker [data-pick]');
  const known = (language) => !!language && !!main.querySelector('[data-pick="' + CSS.escape(language) + '"], .tabs input[data-lang="' + CSS.escape(language) + '"]');

  function pick(language, remember) {
    main.dataset.pick = language;
    for (const button of buttons) button.setAttribute('aria-pressed', String(button.dataset.pick === language));
    for (const group of main.querySelectorAll('.tabs')) {
      const radio = group.querySelector('input[data-lang="' + CSS.escape(language) + '"]');
      if (radio) radio.checked = true;
    }
    if (remember) {
      try { localStorage.setItem(KEY, language); } catch (e) { /* kept for this visit only */ }
      try {
        const url = new URL(location.href);
        url.searchParams.set('lang', language);
        history.replaceState(null, '', url);
      } catch (e) { /* the address stays as it is */ }
    }
  }

  for (const radio of main.querySelectorAll('.tabs input[data-lang]')) {
    radio.addEventListener('change', () => { if (radio.checked) pick(radio.dataset.lang, true); });
  }
  for (const button of buttons) button.addEventListener('click', () => pick(button.dataset.pick, true));
  const picker = main.querySelector('.picker');
  if (picker) picker.hidden = false;
  let asked = '';
  try { asked = new URL(location.href).searchParams.get('lang') || ''; } catch (e) { asked = ''; }
  if (known(asked)) pick(asked, false);
  else if (known(stored)) pick(stored, false);

  // On a phone the page is long: the parity, the calls and the examples start folded under their title, which is
  // the button that opens them. A link that leads inside one (the sub-navigation, an address with a #) opens it.
  // Without script, or on a wide screen, everything is shown.
  const narrow = window.matchMedia('(max-width: 600px)');
  const folds = [];
  for (const id of ['parity', 'calls', 'examples']) {
    const section = document.getElementById(id);
    const head = section && section.querySelector('.section-head');
    const title = head && head.querySelector('h2');
    if (!title) continue;
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'fold-title';
    button.append(...title.childNodes);
    title.append(button);
    const rest = Array.from(section.children).filter((el) => el !== head);
    const lede = Array.from(head.children).filter((el) => el !== title);
    const set = (open) => {
      button.setAttribute('aria-expanded', String(open));
      for (const el of rest.concat(lede)) el.hidden = !open;
    };
    button.addEventListener('click', () => set(button.getAttribute('aria-expanded') !== 'true'));
    folds.push({ section, set });
  }
  const apply = () => {
    for (const fold of folds) {
      fold.section.classList.toggle('folds', narrow.matches);
      fold.set(!narrow.matches || (!!location.hash && fold.section.querySelector(':target') !== null));
    }
  };
  const openFor = () => {
    const target = location.hash && document.getElementById(decodeURIComponent(location.hash.slice(1)));
    for (const fold of folds) if (narrow.matches && target && fold.section.contains(target)) fold.set(true);
    if (target && narrow.matches) target.scrollIntoView();
  };
  narrow.addEventListener('change', apply);
  window.addEventListener('hashchange', openFor);
  apply();
  openFor();
})();
