// The language a visitor chose before boreale-site's lang.js, which keeps it
// as "boreale-lang", the menu's data-lang (the folder, "en-US" for English):
// the old "lantern-lang" (the folder, "en" for English) moved there once,
// then removed. Loaded in <head> before lang.js, whose first visit reads the
// choice. To delete after 2027-01-31 (workbench plans/lantern/suivi.md),
// with its <script> in site/template.html.
(function () {
  try {
    var old = localStorage.getItem("lantern-lang");
    if (old === null) return;
    var code = old.toLowerCase();
    var known = ["en-us", "fr", "fr-ca", "de", "es", "es-419", "it", "nl", "pt", "pt-br", "ru", "ja", "ko",
      "zh-hans", "zh-hant"];
    var folder = code === "en" || code === "en-us" ? "en-US" : known.indexOf(code) >= 0 ? code : null;
    if (folder && localStorage.getItem("boreale-lang") === null) localStorage.setItem("boreale-lang", folder);
    localStorage.removeItem("lantern-lang");
  } catch (e) { /* storage refused: nothing kept */ }
})();
