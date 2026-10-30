// Typing in the header search widget also filters service cards (name/description)
// and hides empty groups. Enter still runs the web search.
(() => {
  let q = "";
  const apply = () => {
    document.querySelectorAll("li.service").forEach((li) => {
      const text = ((li.dataset.name || "") + " " + li.textContent).toLowerCase();
      li.style.display = !q || text.includes(q) ? "" : "none";
    });
    document.querySelectorAll(".services-group").forEach((g) => {
      const any = [...g.querySelectorAll("li.service")].some((li) => li.style.display !== "none");
      g.style.display = any ? "" : "none";
    });
  };

  // delegated, so it works whenever React mounts the widget
  document.addEventListener("input", (e) => {
    if (!e.target.closest(".information-widget-search")) return;
    q = e.target.value.trim().toLowerCase();
    apply();
  });
  // ponytail: re-filter when React re-renders cards (childList only, so our style edits don't loop)
  new MutationObserver(() => q && apply()).observe(document.documentElement, { childList: true, subtree: true });
})();
