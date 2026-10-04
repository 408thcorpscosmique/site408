/*!
 * 408th Corps Cosmique — couche de sécurité côté client
 * -----------------------------------------------------
 * À charger en PREMIER dans <head> (script classique, sans defer/async).
 *
 *  1. Neutralise les XSS : tout HTML injecté via innerHTML / outerHTML /
 *     insertAdjacentHTML est nettoyé (balises dangereuses, attributs on*,
 *     URLs javascript:/data:/vbscript:, CSS exécutable…). Le rendu et les
 *     icônes SVG sont conservés.
 *  2. Bloque toute navigation vers une URL javascript:/data:/vbscript:.
 *  3. Valide les préférences locales (localStorage) avant leur lecture.
 *  4. Expose window.Sec408 = { esc, safeUrl, sanitize, isEmail }.
 *
 * Rappel : ce fichier protège les visiteurs. La protection des DONNÉES
 * reste assurée par les règles Firebase (Firestore / Realtime Database).
 */
(function () {
  "use strict";
  if (window.Sec408) return;

  var SVG_NS = "http://www.w3.org/2000/svg";
  var HTML_NS = "http://www.w3.org/1999/xhtml";

  /* ── Utilitaires ─────────────────────────────────────── */
  var ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"'`]/g, function (c) { return ESC_MAP[c]; }); }

  var EMAIL_RE = /^[^\s@,#$\[\]\/]{1,64}@[^\s@,#$\[\]\/]{1,185}\.[a-z]{2,}$/i;
  function isEmail(s) { return EMAIL_RE.test(String(s || "").trim()); }

  var NAV_PROTOCOLS = ["http:", "https:", "mailto:", "tel:"];
  /**
   * Renvoie l'URL si son protocole est sûr, sinon "#".
   * opts.media = true autorise aussi blob: et data:image/* (pour <img src>).
   */
  function safeUrl(u, opts) {
    u = String(u == null ? "" : u).trim();
    if (!u) return u;
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(u)) return "#";
    var p;
    try { p = new URL(u, location.href); } catch (e) { return "#"; }
    if (NAV_PROTOCOLS.indexOf(p.protocol) !== -1) return u;
    if (opts && opts.media) {
      if (p.protocol === "blob:") return u;
      if (p.protocol === "data:" && /^data:image\/(png|jpe?g|gif|webp|avif|bmp|x-icon|svg\+xml)[;,]/i.test(u)) return u;
    }
    return "#";
  }

  /* ── Sanitizer ───────────────────────────────────────── */
  // Éléments supprimés avec tout leur contenu
  var DROP = {
    SCRIPT:1, IFRAME:1, FRAME:1, FRAMESET:1, OBJECT:1, EMBED:1, APPLET:1, BASE:1, META:1, LINK:1,
    NOSCRIPT:1, TEMPLATE:1, MATH:1, PORTAL:1, STYLE:1, XMP:1, PLAINTEXT:1, NOEMBED:1, NOFRAMES:1,
    // SVG dangereux
    FOREIGNOBJECT:1, ANIMATE:1, SET:1, ANIMATETRANSFORM:1, ANIMATEMOTION:1, HANDLER:1, LISTENER:1
  };
  var URL_ATTRS = { href:1, src:1, action:1, formaction:1, "xlink:href":1, poster:1, background:1, cite:1, data:1, longdesc:1, lowsrc:1, dynsrc:1, ping:1 };
  var MEDIA_TAGS = { IMG:1, SOURCE:1, VIDEO:1, AUDIO:1, TRACK:1, IMAGE:1, INPUT:1 };
  var DROP_ATTRS = { srcdoc:1, formaction:1, ping:1, "http-equiv":1, is:1 };
  var HIDE_ON_ERROR_RE = /^\s*this\.style\.display\s*=\s*['"]none['"]\s*;?\s*$/;
  var BAD_CSS_RE = /expression\s*\(|javascript\s*:|vbscript\s*:|behavior\s*:|-moz-binding|@import|\\/i;
  var CSS_URL_RE = /url\s*\(\s*(['"]?)([\s\S]*?)\1\s*\)/gi;
  function badCss(val) {
    if (BAD_CSS_RE.test(val)) return true;
    var m; CSS_URL_RE.lastIndex = 0;
    while ((m = CSS_URL_RE.exec(val))) {
      var u = m[2].trim();
      if (u && safeUrl(u, { media: true }) !== u) return true;
    }
    return false;
  }

  function cleanAttributes(el) {
    var tag = el.tagName.toUpperCase();
    var attrs = Array.prototype.slice.call(el.attributes);
    for (var i = 0; i < attrs.length; i++) {
      var name = attrs[i].name.toLowerCase();
      var val = attrs[i].value;

      if (name.indexOf("on") === 0) {
        // Conserve le comportement « masquer l'image si erreur » sans exécuter de code
        if (name === "onerror" && HIDE_ON_ERROR_RE.test(val)) el.setAttribute("data-sec-hide-on-error", "");
        el.removeAttribute(attrs[i].name);
        continue;
      }
      if (DROP_ATTRS[name]) { el.removeAttribute(attrs[i].name); continue; }

      if (URL_ATTRS[name]) {
        var media = !!MEDIA_TAGS[tag] && (name === "src" || name === "href" || name === "xlink:href" || name === "poster");
        if (tag === "USE" && (name === "href" || name === "xlink:href")) {
          if (val.trim().charAt(0) !== "#") el.removeAttribute(attrs[i].name);
          continue;
        }
        var safe = safeUrl(val, { media: media });
        if (safe !== val.trim()) el.setAttribute(attrs[i].name, safe);
        continue;
      }
      if (name === "srcset" || name === "imagesrcset") {
        var ok = val.split(",").every(function (part) {
          var u = part.trim().split(/\s+/)[0];
          return !u || safeUrl(u, { media: true }) === u;
        });
        if (!ok) el.removeAttribute(attrs[i].name);
        continue;
      }
      if (name === "style" && badCss(val)) { el.removeAttribute("style"); continue; }
    }
    if (tag === "A" && (el.getAttribute("target") || "").toLowerCase() === "_blank") {
      el.setAttribute("rel", "noopener noreferrer");
    }
  }

  function sanitizeNode(root) {
    var stack = [root];
    while (stack.length) {
      var node = stack.pop();
      var kids = Array.prototype.slice.call(node.childNodes);
      for (var i = 0; i < kids.length; i++) {
        var n = kids[i];
        if (n.nodeType === 3) continue;                    // texte
        if (n.nodeType !== 1) { n.parentNode.removeChild(n); continue; } // commentaires, PI…
        var tag = n.tagName.toUpperCase();
        if (DROP[tag]) { n.parentNode.removeChild(n); continue; }
        cleanAttributes(n);
        stack.push(n);
      }
    }
    return root;
  }

  /* ── Accesseurs natifs ───────────────────────────────── */
  var EP = Element.prototype;
  var innerDesc = Object.getOwnPropertyDescriptor(EP, "innerHTML");
  var outerDesc = Object.getOwnPropertyDescriptor(EP, "outerHTML");
  var nativeInsertAdjacentHTML = EP.insertAdjacentHTML;
  if (!innerDesc || !innerDesc.set) return; // navigateur très ancien : on n'intervient pas
  var setInner = innerDesc.set, getInner = innerDesc.get;

  // Éléments dont le contenu est du texte brut : comportement natif inchangé
  var RAW_TEXT = { SCRIPT:1, STYLE:1, TEXTAREA:1, TITLE:1, XMP:1, NOEMBED:1, NOFRAMES:1, PLAINTEXT:1, IFRAME:1, NOSCRIPT:1 };

  /** Parse le HTML dans un document inerte, le nettoie, renvoie un fragment. */
  function toFragment(html, ctx) {
    html = String(html == null ? "" : html);
    var tpl = document.createElement("template");
    var inSvg = ctx && ctx.namespaceURI === SVG_NS && ctx.localName !== "foreignObject";
    setInner.call(tpl, inSvg ? "<svg>" + html + "</svg>" : html);
    sanitizeNode(tpl.content);
    if (!inSvg) return tpl.content;
    var frag = document.createDocumentFragment();
    var svg = tpl.content.firstElementChild;
    if (svg && svg.localName === "svg") while (svg.firstChild) frag.appendChild(svg.firstChild);
    return frag;
  }

  function sanitize(html, ctx) {
    var frag = toFragment(html, ctx);
    var box = document.createElement("div");
    box.appendChild(frag);
    return getInner.call(box);
  }

  /* ── Hooks sur les sinks HTML ────────────────────────── */
  Object.defineProperty(EP, "innerHTML", {
    configurable: true,
    enumerable: innerDesc.enumerable,
    get: getInner,
    set: function (html) {
      var tag = (this.tagName || "").toUpperCase();
      if (this.namespaceURI === HTML_NS && RAW_TEXT[tag]) { setInner.call(this, html); return; }
      if (tag === "TEMPLATE" && this.namespaceURI === HTML_NS) { setInner.call(this, sanitize(html, this)); return; }
      var frag = toFragment(html, this);
      while (this.firstChild) this.removeChild(this.firstChild);
      this.appendChild(frag);
    }
  });

  if (outerDesc && outerDesc.set) {
    Object.defineProperty(EP, "outerHTML", {
      configurable: true,
      enumerable: outerDesc.enumerable,
      get: outerDesc.get,
      set: function (html) {
        var parent = this.parentNode;
        if (!parent) { outerDesc.set.call(this, html); return; }
        var ctx = parent.nodeType === 1 ? parent : document.body;
        parent.replaceChild(toFragment(html, ctx), this);
      }
    });
  }

  if (nativeInsertAdjacentHTML) {
    EP.insertAdjacentHTML = function (position, html) {
      var pos = String(position).toLowerCase();
      var outside = pos === "beforebegin" || pos === "afterend";
      var ctx = outside ? (this.parentElement || document.body) : this;
      if (!outside && this.namespaceURI === HTML_NS && RAW_TEXT[(this.tagName || "").toUpperCase()]) {
        return nativeInsertAdjacentHTML.call(this, position, html);
      }
      var frag = toFragment(html, ctx);
      if (pos === "beforebegin") { if (this.parentNode) this.parentNode.insertBefore(frag, this); }
      else if (pos === "afterbegin") this.insertBefore(frag, this.firstChild);
      else if (pos === "beforeend") this.appendChild(frag);
      else if (pos === "afterend") { if (this.parentNode) this.parentNode.insertBefore(frag, this.nextSibling); }
      else nativeInsertAdjacentHTML.call(this, position, ""); // lève l'erreur native
    };
  }

  if (window.Range && Range.prototype.createContextualFragment) {
    Range.prototype.createContextualFragment = function (html) {
      var c = this.startContainer;
      var ctx = c && (c.nodeType === 1 ? c : c.parentElement);
      return toFragment(html, ctx || document.body);
    };
  }

  /* ── Navigation : blocage des URL exécutables ────────── */
  function blockBadNav(e) {
    var t = e.target;
    if (!t || !t.closest) return;
    var a = t.closest("a[href], area[href]");
    if (!a) return;
    var raw = a.getAttribute("href");
    if (safeUrl(raw, { media: a.hasAttribute("download") }) === "#" && raw.trim() !== "#") {
      e.preventDefault();
      console.warn("[Sec408] Lien bloqué :", raw.slice(0, 80));
    }
  }
  document.addEventListener("click", blockBadNav, true);
  document.addEventListener("auxclick", blockBadNav, true);

  /* ── Images en erreur (remplace onerror="this.style.display='none'") ── */
  document.addEventListener("error", function (e) {
    var t = e.target;
    if (t && t.hasAttribute && t.hasAttribute("data-sec-hide-on-error")) t.style.display = "none";
  }, true);

  /* ── Préférences locales : validation avant lecture ──── */
  try {
    var KEY = "corps408_ui_prefs_v1";
    var raw = localStorage.getItem(KEY);
    if (raw) {
      var p = null;
      try { p = JSON.parse(raw); } catch (e) { p = null; }
      if (!p || typeof p !== "object" || Array.isArray(p) || raw.length > 100000) {
        localStorage.removeItem(KEY);
      } else {
        var HEX = /^#[0-9a-f]{6}$/i, changed = false;
        ["__proto__", "constructor", "prototype"].forEach(function (k) {
          if (Object.prototype.hasOwnProperty.call(p, k)) { delete p[k]; changed = true; }
        });
        ["primary", "secondary"].forEach(function (k) {
          if (k in p && !HEX.test(String(p[k]))) { delete p[k]; changed = true; }
        });
        if ("theme" in p && ["light", "dark", "auto"].indexOf(p.theme) === -1) { delete p.theme; changed = true; }
        if ("fontSize" in p && !(typeof p.fontSize === "number" && p.fontSize >= 12 && p.fontSize <= 22)) { delete p.fontSize; changed = true; }
        if ("sidebarWidth" in p && !(typeof p.sidebarWidth === "number" && p.sidebarWidth >= 150 && p.sidebarWidth <= 400)) { delete p.sidebarWidth; changed = true; }
        if ("headerDensity" in p && !(typeof p.headerDensity === "number" && p.headerDensity >= 0.5 && p.headerDensity <= 2)) { delete p.headerDensity; changed = true; }
        if ("dashboards" in p) {
          var d = p.dashboards;
          if (!d || typeof d !== "object" || Array.isArray(d)) { delete p.dashboards; changed = true; }
          else Object.keys(d).forEach(function (name) {
            var bad = name.length > 40 || ["__proto__", "constructor", "prototype"].indexOf(name) !== -1 || !Array.isArray(d[name]);
            if (bad) { delete d[name]; changed = true; return; }
            var clean = d[name].filter(function (id) { return typeof id === "string" && /^[a-z0-9_]{1,40}$/i.test(id); });
            if (clean.length !== d[name].length) { d[name] = clean; changed = true; }
          });
        }
        if (changed) localStorage.setItem(KEY, JSON.stringify(p));
      }
    }
  } catch (e) { /* stockage indisponible */ }

  window.Sec408 = Object.freeze({ esc: esc, safeUrl: safeUrl, sanitize: sanitize, isEmail: isEmail });
})();
