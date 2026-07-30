/* VPN Panel — mavzu almashtirish, modallar, jonli dashboard va grafik. */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* ------------------------------------------------------------- formatlash */

  function bits(bps) {
    if (!bps || bps < 1) return "0 bit/s";
    var units = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"];
    var i = 0;
    while (bps >= 1000 && i < units.length - 1) { bps /= 1000; i++; }
    return (bps >= 100 || i === 0 ? Math.round(bps) : bps.toFixed(1)) + " " + units[i];
  }

  function bytes(value) {
    if (!value) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = 0;
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
    return (value >= 100 || i === 0 ? Math.round(value) : value.toFixed(1)) + " " + units[i];
  }

  function duration(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    var d = Math.floor(seconds / 86400);
    var h = Math.floor((seconds % 86400) / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    if (d) return d + " kun " + h + " soat";
    if (h) return h + " soat " + m + " daq";
    if (m) return m + " daq";
    return seconds + " soniya";
  }

  /* ----------------------------------------------------------------- mavzu */

  function initTheme() {
    $$("[data-theme-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var root = document.documentElement;
        var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem("vpn-theme", next); } catch (e) {}
        syncThemeLabels();
      });
    });
    syncThemeLabels();
    document.body.classList.add("theme-ready");
  }

  function syncThemeLabels() {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    $$("[data-theme-label]").forEach(function (el) { el.textContent = dark ? "Yorug' mavzu" : "Qorong'i mavzu"; });
    $$("[data-theme-icon]").forEach(function (el) { el.style.display = (el.dataset.themeIcon === (dark ? "sun" : "moon")) ? "" : "none"; });
  }

  /* --------------------------------------------------------------- modallar */

  function openModal(id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.classList.add("open");
    var focusable = el.querySelector("input:not([type=hidden]), button");
    if (focusable) setTimeout(function () { focusable.focus(); }, 30);
  }

  function closeModal(el) { el.classList.remove("open"); }

  function initModals() {
    $$("[data-modal-open]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.dataset.modalOpen;
        var target = document.getElementById(id);
        if (target) {
          // Bir modal bir nechta qator uchun ishlatilsa, qiymatlarni ko'chiramiz.
          Object.keys(btn.dataset).forEach(function (key) {
            if (key.indexOf("fill") === 0) {
              var name = key.slice(4).toLowerCase();
              $$("[data-slot='" + name + "']", target).forEach(function (slot) {
                if (slot.tagName === "INPUT") slot.value = btn.dataset[key];
                else slot.textContent = btn.dataset[key];
              });
              $$("[data-action-template]", target).forEach(function (form) {
                form.setAttribute("action", form.dataset.actionTemplate.replace("__USER__", btn.dataset[key]));
              });
            }
          });
        }
        openModal(id);
      });
    });

    $$("[data-modal-close]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var backdrop = btn.closest(".modal-backdrop");
        if (backdrop) closeModal(backdrop);
      });
    });

    $$(".modal-backdrop").forEach(function (backdrop) {
      backdrop.addEventListener("mousedown", function (event) {
        if (event.target === backdrop) closeModal(backdrop);
      });
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") $$(".modal-backdrop.open").forEach(closeModal);
    });
  }

  /* ------------------------------------------------- tasdiqlash oynasi */

  function initConfirm() {
    var backdrop = $("#confirm-modal");
    if (!backdrop) return;
    var pending = null;

    $$("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (form.dataset.confirmed === "1") return;
        event.preventDefault();
        pending = form;
        $("[data-slot='message']", backdrop).textContent = form.dataset.confirm;
        $("[data-slot='title']", backdrop).textContent = form.dataset.confirmTitle || "Tasdiqlang";
        openModal("confirm-modal");
      });
    });

    $("[data-confirm-ok]", backdrop).addEventListener("click", function () {
      if (!pending) return;
      pending.dataset.confirmed = "1";
      closeModal(backdrop);
      pending.submit();
      pending = null;
    });
  }

  /* --------------------------------------------------------------- parollar */

  var ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";

  function generatePassword(length) {
    var out = "";
    var buf = new Uint32Array(length);
    (window.crypto || window.msCrypto).getRandomValues(buf);
    for (var i = 0; i < length; i++) out += ALPHABET[buf[i] % ALPHABET.length];
    return out;
  }

  function strength(value) {
    if (!value) return 0;
    var classes = 0;
    if (/[a-z]/.test(value)) classes++;
    if (/[A-Z]/.test(value)) classes++;
    if (/[0-9]/.test(value)) classes++;
    if (/[^a-zA-Z0-9]/.test(value)) classes++;
    var score = 0;
    if (value.length >= 10) score++;
    if (value.length >= 14) score++;
    if (classes >= 3) score++;
    if (classes >= 4 && value.length >= 12) score++;
    return score;
  }

  function initPasswords() {
    $$("[data-generate]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var input = document.getElementById(btn.dataset.generate);
        if (!input) return;
        input.type = "text";
        input.value = generatePassword(18);
        input.dispatchEvent(new Event("input"));
      });
    });

    $$("[data-reveal]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var input = document.getElementById(btn.dataset.reveal);
        if (input) input.type = input.type === "password" ? "text" : "password";
      });
    });

    $$("[data-meter-for]").forEach(function (meter) {
      var input = document.getElementById(meter.dataset.meterFor);
      if (!input) return;
      var bars = $$("i", meter);
      var update = function () {
        var score = strength(input.value);
        bars.forEach(function (bar, index) { bar.classList.toggle("on", index < score); });
      };
      input.addEventListener("input", update);
      update();
    });
  }

  /* ----------------------------------------------------------------- grafik */

  function drawChart(svg, history) {
    var width = svg.clientWidth || svg.parentNode.clientWidth || 600;
    var height = svg.clientHeight || 168;
    // Pastdagi bo'shliq: trafik nolga teng bo'lganda chiziq karta chetiga
    // yopishib qolmaydi, alohida ko'rinib turadi.
    var pad = { top: 10, right: 4, bottom: 12, left: 4 };
    var innerW = Math.max(1, width - pad.left - pad.right);
    var innerH = Math.max(1, height - pad.top - pad.bottom);

    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    if (!history.length) return;

    var peak = 0;
    history.forEach(function (point) { peak = Math.max(peak, point.down, point.up); });
    // Trafik umuman bo'lmaganda chiziqlar so'niq chiziladi — bo'sh grafik
    // haqiqiy nol tezlikdan ajralib turadi.
    var idle = peak <= 0;
    var scaleMax = (peak || 1) * 1.25;

    var stepX = history.length > 1 ? innerW / (history.length - 1) : innerW;
    var pointsFor = function (key) {
      return history.map(function (point, index) {
        return [pad.left + index * stepX, pad.top + innerH - (point[key] / scaleMax) * innerH];
      });
    };

    // Yumshoq egri chiziq (Catmull-Rom -> kubik Bezier).
    var pathFrom = function (points) {
      if (points.length < 2) return "M" + points[0][0] + "," + points[0][1];
      var d = "M" + points[0][0] + "," + points[0][1];
      for (var i = 0; i < points.length - 1; i++) {
        var p0 = points[i === 0 ? 0 : i - 1], p1 = points[i], p2 = points[i + 1];
        var p3 = points[i + 2] || p2;
        d += "C" + (p1[0] + (p2[0] - p0[0]) / 6) + "," + (p1[1] + (p2[1] - p0[1]) / 6) +
             " " + (p2[0] - (p3[0] - p1[0]) / 6) + "," + (p2[1] - (p3[1] - p1[1]) / 6) +
             " " + p2[0] + "," + p2[1];
      }
      return d;
    };

    var ns = "http://www.w3.org/2000/svg";
    var make = function (tag, attrs) {
      var node = document.createElementNS(ns, tag);
      Object.keys(attrs).forEach(function (key) { node.setAttribute(key, attrs[key]); });
      return node;
    };

    // Gorizontal to'r.
    [0.25, 0.5, 0.75].forEach(function (fraction) {
      svg.appendChild(make("line", {
        x1: pad.left, x2: pad.left + innerW,
        y1: pad.top + innerH * fraction, y2: pad.top + innerH * fraction,
        stroke: "currentColor", "stroke-opacity": ".08", "stroke-width": "1"
      }));
    });

    var downPoints = pointsFor("down");
    var area = pathFrom(downPoints) +
      "L" + downPoints[downPoints.length - 1][0] + "," + (pad.top + innerH) +
      "L" + downPoints[0][0] + "," + (pad.top + innerH) + "Z";

    var gradientId = "grad-" + Math.abs(width | 0);
    var defs = make("defs", {});
    var gradient = make("linearGradient", { id: gradientId, x1: "0", y1: "0", x2: "0", y2: "1" });
    gradient.appendChild(make("stop", { offset: "0%", "stop-color": "currentColor", "stop-opacity": ".22" }));
    gradient.appendChild(make("stop", { offset: "100%", "stop-color": "currentColor", "stop-opacity": "0" }));
    defs.appendChild(gradient);
    svg.appendChild(defs);

    if (!idle) {
      svg.appendChild(make("path", { d: area, fill: "url(#" + gradientId + ")", stroke: "none" }));
    }
    svg.appendChild(make("path", {
      d: pathFrom(downPoints), fill: "none", stroke: "currentColor",
      "stroke-width": idle ? "1.5" : "2", "stroke-opacity": idle ? ".22" : "1",
      "stroke-linecap": "round", "stroke-linejoin": "round"
    }));
    svg.appendChild(make("path", {
      d: pathFrom(pointsFor("up")), fill: "none", stroke: "currentColor",
      "stroke-width": "1.5", "stroke-opacity": idle ? ".14" : ".45",
      "stroke-dasharray": "4 4", "stroke-linecap": "round"
    }));

    if (!idle) {
      var last = downPoints[downPoints.length - 1];
      svg.appendChild(make("circle", { cx: last[0], cy: last[1], r: "3", fill: "currentColor" }));
    }

    var peakLabel = svg.parentNode.parentNode.querySelector("[data-chart-peak]");
    if (peakLabel) peakLabel.textContent = idle ? "Cho'qqi —" : "Cho'qqi " + bits(peak);
  }

  /* ------------------------------------------------------------ jonli holat */

  function renderClients(tbody, clients) {
    if (!clients.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">Hozircha hech kim ulanmagan</td></tr>';
      return;
    }
    var now = Math.floor(Date.now() / 1000);
    tbody.innerHTML = clients.map(function (client) {
      var initial = (client.name[0] || "?").toUpperCase();
      return '<tr>' +
        '<td><div class="user-cell"><div class="avatar">' + escapeHtml(initial) + '</div>' +
          '<div class="meta"><div class="name">' + escapeHtml(client.name) + '</div>' +
          '<div class="sub mono">' + escapeHtml(client.vpn_address || "—") + '</div></div></div></td>' +
        // data-label — mobil rejimda qator kartaga aylanganda ustun nomi bo'lib chiqadi.
        '<td class="mono" data-label="IP manzil">' + escapeHtml((client.real_address || "").split(":")[0]) + '</td>' +
        '<td class="num" data-label="Davomiyligi">' + duration(now - client.connected_since) + '</td>' +
        '<td class="right num" data-label="Tezlik">' + bits(client.down_bps) + ' &middot; ' + bits(client.up_bps) + '</td>' +
        '<td class="right num" data-label="Trafik">' + bytes(client.bytes_received + client.bytes_sent) + '</td>' +
        '<td class="actions">' + disconnectForm(client.name) + '</td>' +
      '</tr>';
    }).join("");
  }

  function disconnectForm(name) {
    var token = document.body.dataset.csrf;
    return '<form method="post" action="/users/' + encodeURIComponent(name) + '/disconnect" ' +
      'data-confirm="' + escapeHtml(name) + ' ulanishi uziladi." class="inline-form">' +
      '<input type="hidden" name="csrf_token" value="' + escapeHtml(token) + '">' +
      '<button class="btn btn-sm btn-quiet" type="submit">Uzish</button></form>';
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function initLive() {
    var root = $("[data-live]");
    if (!root) return;

    var svg = $("[data-chart]");
    var tbody = $("[data-clients-body]");
    var history = [];
    try { history = JSON.parse(root.dataset.history || "[]"); } catch (e) {}

    var paint = function (data) {
      if (svg) drawChart(svg, history);
      $$("[data-bind]").forEach(function (el) {
        var path = el.dataset.bind;
        var value = path.split(".").reduce(function (acc, key) { return acc == null ? acc : acc[key]; }, data);
        if (value == null) return;
        if (el.dataset.format === "bits") el.textContent = bits(value);
        else if (el.dataset.format === "bytes") el.textContent = bytes(value);
        else el.textContent = value;
      });
    };

    if (svg) drawChart(svg, history);
    window.addEventListener("resize", function () { if (svg) drawChart(svg, history); });

    var tick = function () {
      fetch("/api/status", { headers: { "Accept": "application/json" }, credentials: "same-origin" })
        .then(function (response) {
          if (response.status === 401 || response.redirected) { window.location.reload(); return null; }
          return response.ok ? response.json() : null;
        })
        .then(function (data) {
          if (!data) return;
          history = data.history || [];
          paint(data);
          if (tbody) { renderClients(tbody, data.clients || []); initConfirm(); }
          var indicator = $("[data-live-dot]");
          if (indicator) indicator.classList.toggle("pulse", !!(data.server && data.server.online));
        })
        .catch(function () { /* tarmoq uzilishi — keyingi urinishda tiklanadi */ });
    };

    setInterval(tick, 5000);
  }

  /* ------------------------------------------------------------------ start */

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initModals();
    initConfirm();
    initPasswords();
    initLive();
  });
})();
