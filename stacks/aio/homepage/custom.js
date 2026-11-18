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

// Pin ONLY the search bar: measure its resting geometry into CSS vars on
// <html>, then add .hl-stuck once the search would naturally scroll past the
// top; custom.css lifts it into position: fixed there. The scroller is
// #inner_wrapper (html/body are height:100%) and scroll does not bubble, so
// the listener is capture-phase on document.
(() => {
  const root = document.documentElement;
  const rowEl = () => document.getElementById("information-widgets-right");
  const scrollY = () => {
    const iw = document.getElementById("inner_wrapper");
    return (iw ? iw.scrollTop : 0) || window.scrollY || 0;
  };
  let base = null; // document-space top of the search form when unscrolled
  const measure = () => {
    const row = rowEl();
    const search = row && row.querySelector(".information-widget-search");
    if (!row || !search || root.classList.contains("hl-stuck")) return;
    root.style.removeProperty("--hl-row-h"); // avoid ratcheting on our own min-height
    const rect = search.getBoundingClientRect();
    base = rect.top + scrollY();
    root.style.setProperty("--hl-row-h", row.offsetHeight + "px");
    root.style.setProperty("--hl-s-left", Math.max(0, rect.left) + "px");
    root.style.setProperty("--hl-s-width", rect.width + "px");
  };
  let measurePending = false;
  let wasStuck = false;
  const onScroll = () => {
    const stuck = base !== null && scrollY() >= base;
    root.classList.toggle("hl-stuck", stuck);
    if (wasStuck && !stuck) measure(); // refresh resting geometry after resize-while-stuck
    wasStuck = stuck;
  };
  const onResize = () => {
    root.classList.remove("hl-stuck");
    wasStuck = false;
    measure();
    onScroll();
  };
  const scheduleMeasure = () => {
    if (measurePending) return;
    measurePending = true;
    requestAnimationFrame(() => {
      measurePending = false;
      measure();
      onScroll();
    });
  };
  measure();
  onScroll();
  addEventListener("resize", onResize, { passive: true });
  document.addEventListener("scroll", onScroll, true);
  // rAF-debounced: homepage status polling mutates constantly and measure()
  // forces layout
  new MutationObserver(scheduleMeasure).observe(root, { childList: true, subtree: true });
})();
