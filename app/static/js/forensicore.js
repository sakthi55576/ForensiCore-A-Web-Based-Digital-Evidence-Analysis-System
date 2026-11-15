/* ==========================================================================
   FORENSICORE — shared UI behaviour
   Small, dependency-free helpers only. No backend calls, no state changes
   beyond the current page's DOM.
   ========================================================================== */

document.addEventListener("DOMContentLoaded", function () {

  /* ---------------------------------------------------------------
     Sidebar toggle (mobile / tablet)
     --------------------------------------------------------------- */

  var sidebar = document.querySelector(".fc-sidebar");
  var backdrop = document.querySelector(".fc-sidebar-backdrop");
  var toggleButtons = document.querySelectorAll("[data-fc-sidebar-toggle]");

  function closeSidebar() {
    if (sidebar) sidebar.classList.remove("open");
    if (backdrop) backdrop.classList.remove("open");
  }

  function openSidebar() {
    if (sidebar) sidebar.classList.add("open");
    if (backdrop) backdrop.classList.add("open");
  }

  toggleButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      if (sidebar && sidebar.classList.contains("open")) {
        closeSidebar();
      } else {
        openSidebar();
      }
    });
  });

  if (backdrop) {
    backdrop.addEventListener("click", closeSidebar);
  }

  /* ---------------------------------------------------------------
     Copy-to-clipboard for hash values
     --------------------------------------------------------------- */

  document.querySelectorAll("[data-copy-value]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var value = btn.getAttribute("data-copy-value") || "";

      var finish = function () {
        var icon = btn.querySelector("i");
        var originalClass = icon ? icon.className : null;

        btn.classList.add("copied");
        if (icon) icon.className = "bi bi-check-lg";

        setTimeout(function () {
          btn.classList.remove("copied");
          if (icon && originalClass) icon.className = originalClass;
        }, 1500);
      };

      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(value).then(finish).catch(function () {
          fallbackCopy(value);
          finish();
        });
      } else {
        fallbackCopy(value);
        finish();
      }
    });
  });

  function fallbackCopy(text) {
    var temp = document.createElement("textarea");
    temp.value = text;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    document.body.appendChild(temp);
    temp.focus();
    temp.select();
    try {
      document.execCommand("copy");
    } catch (err) {
      /* clipboard unavailable — silently ignore, value stays selected */
    }
    document.body.removeChild(temp);
  }

  /* ---------------------------------------------------------------
     Password visibility toggle
     --------------------------------------------------------------- */

  document.querySelectorAll("[data-password-toggle]").forEach(function (btn) {
    var targetId = btn.getAttribute("data-password-toggle");
    var input = document.getElementById(targetId);
    if (!input) return;

    btn.addEventListener("click", function () {
      var isHidden = input.getAttribute("type") === "password";
      input.setAttribute("type", isHidden ? "text" : "password");

      var icon = btn.querySelector("i");
      if (icon) {
        icon.className = isHidden ? "bi bi-eye-slash" : "bi bi-eye";
      }
    });
  });

});


/* ==========================================================================
   Case workspace helpers
   - open the tab named in the URL hash (#tab-evidence) and keep it in sync
   - filter chips for the Findings and Timeline lists
   - confirm before re-running an integrity check on large files (no-op)
   ========================================================================== */
document.addEventListener("DOMContentLoaded", function () {
  // ---- tabs <-> URL hash ----
  var hash = window.location.hash;
  if (hash && window.bootstrap) {
    var trigger = document.querySelector('[data-bs-target="' + hash + '"]');
    if (trigger) {
      window.bootstrap.Tab.getOrCreateInstance(trigger).show();
    }
  }
  document.querySelectorAll('.fc-tabs [data-bs-toggle="tab"]').forEach(function (tab) {
    tab.addEventListener("shown.bs.tab", function (event) {
      var target = event.target.getAttribute("data-bs-target");
      if (target && history.replaceState) {
        history.replaceState(null, "", target);
      }
    });
  });

  // ---- filter chips: <button data-filter-group="findings" data-filter="HIGH"> ----
  document.querySelectorAll("[data-filter-group]").forEach(function (chip) {
    chip.addEventListener("click", function () {
      var group = chip.getAttribute("data-filter-group");
      var value = chip.getAttribute("data-filter");

      document.querySelectorAll('[data-filter-group="' + group + '"]').forEach(function (c) {
        c.classList.toggle("active", c === chip);
      });

      document.querySelectorAll('[data-filter-item="' + group + '"]').forEach(function (item) {
        var match = value === "ALL" || item.getAttribute("data-filter-value") === value;
        item.classList.toggle("d-none", !match);
      });
    });
  });
});
