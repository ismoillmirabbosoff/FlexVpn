/* Mavzuni birinchi chizishdan oldin qo'yamiz — shunda sahifa "oq chaqnab" ketmaydi. */
(function () {
  try {
    var saved = localStorage.getItem("vpn-theme");
    var dark = saved ? saved === "dark"
                     : window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
