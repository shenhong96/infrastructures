// Filter box: hides service cards whose name/description don't match, and empty groups.
(() => {
  const box = document.createElement("input");
  box.type = "search";
  box.placeholder = "Filter services…";
  box.setAttribute("aria-label", "Filter services");
  box.style.cssText =
    "position:fixed;top:12px;right:12px;z-index:50;padding:6px 10px;border-radius:8px;" +
    "border:1px solid rgba(255,255,255,.3);background:rgba(0,0,0,.5);color:#fff;width:200px";

  const apply = () => {
    const q = box.value.trim().toLowerCase();
    document.querySelectorAll("li.service").forEach((li) => {
      const text = ((li.dataset.name || "") + " " + li.textContent).toLowerCase();
      li.style.display = !q || text.includes(q) ? "" : "none";
    });
    document.querySelectorAll(".services-group").forEach((g) => {
      const any = [...g.querySelectorAll("li.service")].some((li) => li.style.display !== "none");
      g.style.display = any ? "" : "none";
    });
  };

  box.addEventListener("input", apply);
  box.addEventListener("keydown", (e) => {
    e.stopPropagation(); // keep homepage's quicklaunch from grabbing keystrokes
    if (e.key === "Escape") { box.value = ""; apply(); }
  });
  document.body.appendChild(box);
  // ponytail: re-filter when React re-renders cards (childList only, so our style edits don't loop)
  new MutationObserver(() => box.value && apply()).observe(document.body, { childList: true, subtree: true });
})();
