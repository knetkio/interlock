// CSRF auto-attach.
// The admin AuthMiddleware enforces X-CSRF-Token on every unsafe (POST/PUT/PATCH/DELETE)
// request. The token is delivered to the browser via the readable `interlock_admin_csrf`
// cookie. This block reads it once per request and writes it to the htmx header bag
// on the `htmx:configRequest` event, so individual forms never have to do it.
function _interlockReadCookie(name) {
    var match = ('; ' + document.cookie).match(new RegExp('; ' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
}

var _interlockLastModalTrigger = null;

function _interlockFocusable(root) {
    return Array.prototype.slice.call(root.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), ' +
        'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )).filter(function(element) {
        return !element.hidden && element.getAttribute('aria-hidden') !== 'true';
    });
}

function _interlockActivateModal(root) {
    var dialog = root && root.querySelector('[role="dialog"][aria-modal="true"]');
    if (!dialog) {
        return;
    }
    var focusable = _interlockFocusable(dialog);
    (focusable[0] || dialog).focus();
}

document.addEventListener('htmx:configRequest', function(event) {
    var method = (event.detail.verb || '').toLowerCase();
    if (method === 'post' || method === 'put' || method === 'patch' || method === 'delete') {
        var token = _interlockReadCookie('interlock_admin_csrf');
        if (token) {
            event.detail.headers['X-CSRF-Token'] = token;
        }
    }
});


// Dashboard interactivity - tab and sidebar active state management
document.addEventListener('htmx:afterRequest', function(event) {
    var elt = event.detail.elt;

    // Filter tab active state toggle
    if (elt.classList && elt.classList.contains('filter-tab')) {
        var parent = elt.closest('.filter-tabs');
        if (parent) {
            parent.querySelectorAll('.filter-tab').forEach(function(tab) {
                tab.classList.remove('active');
            });
            elt.classList.add('active');
        }
    }

    // Sidebar navigation active state toggle
    if (elt.closest && elt.closest('.nav-links')) {
        document.querySelectorAll('.nav-links a').forEach(function(link) {
            link.classList.remove('active');
        });
        elt.classList.add('active');
    }
});

// Discovery tab active state (same pattern)
document.addEventListener('htmx:afterRequest', function(event) {
    var elt = event.detail.elt;
    if (elt.classList && elt.classList.contains('disc-tab')) {
        var parent = elt.closest('.disc-tabs');
        if (parent) {
            parent.querySelectorAll('.disc-tab').forEach(function(tab) {
                tab.classList.remove('active');
            });
            elt.classList.add('active');
        }
    }
});

// SQL preview expand/collapse
document.addEventListener('click', function(event) {
    if (event.target.classList.contains('sql-toggle')) {
        var preview = event.target.previousElementSibling;
        if (preview && preview.classList.contains('sql-preview')) {
            preview.classList.toggle('collapsed');
            event.target.textContent = preview.classList.contains('collapsed') ? 'Show more' : 'Show less';
        }
    }
});

function interlockGrantOptions() {
    var root = document.getElementById('source-role-grants');
    return root ? JSON.parse(root.dataset.roleOptions || '{}') : {};
}

function interlockResetRoleSelect(roleSelect) {
    roleSelect.replaceChildren();
    var option = document.createElement('option');
    option.value = '';
    option.textContent = 'Select role';
    roleSelect.appendChild(option);
}

function interlockUpdateGrantRoleOptions(select) {
    var row = select.closest('.source-role-row');
    if (!row) return;
    var roleSelect = row.querySelector('.grant-role-select');
    if (!roleSelect) return;
    var selected = roleSelect.dataset.selected || roleSelect.value;
    var options = interlockGrantOptions()[select.value] || [];
    interlockResetRoleSelect(roleSelect);
    options.forEach(function(role) {
        var roleId = String(role.id || '');
        var roleKey = role.role_key || role.name || role;
        var roleName = role.name || roleKey;
        var label = roleName + ' (' + roleKey + ')' + (role.review_required ? ' - review' : '');
        var option = document.createElement('option');
        option.value = roleId;
        option.dataset.roleKey = roleKey;
        option.textContent = label;
        option.selected = roleId === selected;
        roleSelect.appendChild(option);
    });
    roleSelect.dataset.selected = '';
}

function interlockAddGrantRow() {
    var root = document.getElementById('source-role-grants');
    var first = root ? root.querySelector('.source-role-row') : null;
    if (!first) return;
    var clone = first.cloneNode(true);
    clone.querySelector('.grant-source-select').value = '';
    var roleSelect = clone.querySelector('.grant-role-select');
    interlockResetRoleSelect(roleSelect);
    roleSelect.dataset.selected = '';
    root.appendChild(clone);
}

function interlockRemoveGrantRow(button) {
    var root = document.getElementById('source-role-grants');
    if (!root) return;
    var rows = root.querySelectorAll('.source-role-row');
    if (rows.length === 1) {
        rows[0].querySelector('.grant-source-select').value = '';
        interlockResetRoleSelect(rows[0].querySelector('.grant-role-select'));
        return;
    }
    button.closest('.source-role-row').remove();
}

// Statement rows are rendered by the server (statement-row route), so adding
// one is an htmx request on the Add button; removing the last row asks the
// server for a fresh one rather than clearing selects by hand.
function interlockRemovePermissionRow(button) {
    var root = document.getElementById('permission-statements');
    if (!root) return;
    button.closest('.permission-row').remove();
    if (!root.querySelector('.permission-row')) {
        var add = document.querySelector('.js-add-permission-row');
        if (add && window.htmx) {
            window.htmx.trigger(add, 'click');
        }
    }
}

function interlockUpdateSourceType(select) {
    var option = select.options[select.selectedIndex];
    var sourceType = option ? (option.dataset.sourceType || select.value) : select.value;
    var family = option ? (option.dataset.family || sourceType) : sourceType;
    var sourceTypeInput = document.querySelector('#source-form input[name="source_type"]');
    if (sourceTypeInput) {
        sourceTypeInput.value = sourceType;
    }
    var cache = option ? option.dataset.cache : null;
    var cacheSelect = document.querySelector('#source-form select[name="cache_strategy"]');
    if (cache && cacheSelect && !cacheSelect.dataset.userTouched) {
        cacheSelect.value = cache;
    }
    document.querySelectorAll('.type-block').forEach(function(block) {
        var connectors = (block.dataset.connector || '').split(',');
        var active = select.value === 'fabric_sql' ? connectors.indexOf(select.value) !== -1 : block.dataset.type === select.value ||
            block.dataset.family === family ||
            connectors.indexOf(select.value) !== -1;
        block.hidden = !active;
        block.querySelectorAll('input, select, textarea').forEach(function(input) {
            input.disabled = !active;
        });
    });
    var testButton = document.querySelector('#source-form [hx-post="/dashboard/data-sources/test"]');
    if (testButton) { testButton.disabled = select.value === 'fabric_sql'; testButton.title = testButton.disabled ? 'Save the source first' : ''; }
    interlockFabricFields(document);
}

function interlockCloseModal(rootId) {
    var target = document.getElementById(rootId || '');
    if (target) {
        target.replaceChildren();
    }
    if (_interlockLastModalTrigger && document.contains(_interlockLastModalTrigger)) {
        _interlockLastModalTrigger.focus();
    }
    _interlockLastModalTrigger = null;
}

function interlockWizardConnectorChanged(select) {
    var option = select.options[select.selectedIndex];
    var sourceTypeInput = document.querySelector('#wizard-form input[name="source_type"]');
    if (sourceTypeInput && option) {
        sourceTypeInput.value = option.dataset.sourceType || select.value;
    }
}

function interlockFabricFields(root) {
    (root || document).querySelectorAll('.js-fabric-auth-mode').forEach(function(select) {
        var field = select.closest('.fabric-fields').querySelector('.js-fabric-spn');
        field.hidden = select.value !== 'spn';
        field.querySelector('input').disabled = field.hidden || select.disabled;
    });
    (root || document).querySelectorAll('.js-fabric-picker').forEach(function(icon) {
        var select = icon.closest('label').querySelector('select');
        icon.hidden = select.value !== 'fabric_sql';
    });
}
document.addEventListener('change', function(event) {
    if (event.target.matches('.js-fabric-auth-mode, .js-source-type-select, .js-wizard-connector-select')) interlockFabricFields(document);
});
function interlockInitDynamicForms(root) {
    (root || document).querySelectorAll('.grant-source-select').forEach(interlockUpdateGrantRoleOptions);
    (root || document).querySelectorAll('.js-source-type-select').forEach(interlockUpdateSourceType);
    interlockFabricFields(root);
    (root || document).querySelectorAll('.js-wizard-connector-select').forEach(interlockWizardConnectorChanged);
}

document.addEventListener('change', function(event) {
    if (event.target.classList.contains('grant-source-select')) {
        interlockUpdateGrantRoleOptions(event.target);
    }
    if (event.target.classList.contains('js-source-type-select')) {
        interlockUpdateSourceType(event.target);
    }
    if (event.target.classList.contains('js-wizard-connector-select')) {
        interlockWizardConnectorChanged(event.target);
    }
    if (event.target.matches('#source-form select[name="cache_strategy"]')) {
        event.target.dataset.userTouched = 'true';
    }
    if (event.target.classList.contains('js-toggle-custom-api-key')) {
        var target = document.getElementById(event.target.dataset.toggleTarget || '');
        if (target) {
            target.classList.toggle('hidden', event.target.checked);
        }
    }
});

document.addEventListener('click', function(event) {
    var modalTrigger = event.target.closest ? event.target.closest('[hx-target="#source-modal-root"]') : null;
    if (modalTrigger) {
        _interlockLastModalTrigger = modalTrigger;
    }
    if (event.target.classList.contains('js-add-grant-row')) {
        interlockAddGrantRow();
    }
    if (event.target.classList.contains('js-remove-grant-row')) {
        interlockRemoveGrantRow(event.target);
    }
    var catalogPick = event.target.closest ? event.target.closest('.js-catalog-pick') : null;
    if (catalogPick) {
        interlockCatalogPick(catalogPick);
    }
    if (event.target.classList.contains('js-remove-permission-row')) {
        interlockRemovePermissionRow(event.target);
    }
    if (event.target.classList.contains('js-clear-target')) {
        var target = document.getElementById(event.target.dataset.clearTarget || '');
        if (target) {
            target.replaceChildren();
        }
    }
    if (event.target.classList.contains('js-toggle-hidden')) {
        var hiddenTarget = document.getElementById(event.target.dataset.toggleTarget || '');
        if (hiddenTarget) {
            hiddenTarget.classList.toggle('hidden');
        }
    }
    if (event.target.classList.contains('js-close-modal')) {
        interlockCloseModal(event.target.dataset.modalRoot || '');
    }
    if (event.target.classList.contains('js-modal-backdrop')) {
        interlockCloseModal(event.target.dataset.modalRoot || '');
    }
    if (event.target.classList.contains('js-tree-toggle')) {
        event.target.textContent = event.target.textContent === '+' ? '-' : '+';
    }
    var navTarget = event.target.closest ? event.target.closest('.js-navigate') : null;
    if (navTarget && !event.target.closest('a, button, input, select, textarea')) {
        var href = navTarget.dataset.href;
        if (href) {
            window.location.href = href;
        }
    }
    if (event.target.classList.contains('js-copy-secret') || event.target.classList.contains('js-copy-text')) {
        var button = event.target;
        var secret = button.dataset.copyText || '';
        navigator.clipboard.writeText(secret)
            .then(function() {
                button.textContent = 'Copied';
            })
            .catch(function() {
                button.textContent = 'Copy failed';
            });
    }
});

document.addEventListener('keydown', function(event) {
    var openDialog = document.querySelector('.modal-backdrop [role="dialog"][aria-modal="true"]');
    if (event.key === 'Tab' && openDialog) {
        var focusable = _interlockFocusable(openDialog);
        if (!focusable.length) {
            event.preventDefault();
            openDialog.focus();
        } else if (event.shiftKey && document.activeElement === focusable[0]) {
            event.preventDefault();
            focusable[focusable.length - 1].focus();
        } else if (!event.shiftKey && document.activeElement === focusable[focusable.length - 1]) {
            event.preventDefault();
            focusable[0].focus();
        }
    }
    if (event.key === 'Escape') {
        document.querySelectorAll('.modal-backdrop[data-modal-root]').forEach(function(modal) {
            interlockCloseModal(modal.dataset.modalRoot || '');
        });
    }
});

document.addEventListener('DOMContentLoaded', function() {
    interlockInitDynamicForms(document);
});

document.addEventListener('htmx:afterSwap', function(event) {
    var target = event.detail.target || document;
    interlockInitDynamicForms(target);
    _interlockActivateModal(target);
    if (target.id === 'main-content') {
        target.focus();
        var liveRegion = document.getElementById('admin-live-region');
        var heading = target.querySelector('h1, h2');
        if (liveRegion && heading) {
            liveRegion.textContent = heading.textContent + ' loaded';
        }
    }
});

/* ---------------------------------------------------------------------------
 * Mobile navigation drawer.
 *
 * Below 900px the sidebar is off-canvas. It used to become a horizontal strip
 * whose later items scrolled off screen and could not be reached at all.
 * ------------------------------------------------------------------------ */

function _interlockNavElements() {
    return {
        nav: document.getElementById('primary-nav'),
        toggle: document.querySelector('.js-nav-toggle'),
        scrim: document.querySelector('.js-nav-scrim')
    };
}

function interlockSetNavOpen(open) {
    var el = _interlockNavElements();
    if (!el.nav || !el.toggle) {
        return;
    }
    el.nav.classList.toggle('is-open', open);
    el.toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    el.toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    if (el.scrim) {
        el.scrim.classList.toggle('is-open', open);
        if (open) {
            el.scrim.removeAttribute('hidden');
        } else {
            el.scrim.setAttribute('hidden', '');
        }
    }
    if (open) {
        var first = el.nav.querySelector('a, button');
        if (first) {
            first.focus();
        }
    }
}

document.addEventListener('click', function(event) {
    if (event.target.closest && event.target.closest('.js-nav-toggle')) {
        var nav = document.getElementById('primary-nav');
        interlockSetNavOpen(!(nav && nav.classList.contains('is-open')));
        return;
    }
    if (event.target.closest && event.target.closest('.js-nav-scrim')) {
        interlockSetNavOpen(false);
        return;
    }
    // Following a link should not leave the drawer covering the page.
    if (event.target.closest && event.target.closest('#primary-nav a')) {
        interlockSetNavOpen(false);
    }
});

document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        var nav = document.getElementById('primary-nav');
        if (nav && nav.classList.contains('is-open')) {
            interlockSetNavOpen(false);
            var toggle = document.querySelector('.js-nav-toggle');
            if (toggle) {
                toggle.focus();
            }
        }
    }
});

/* ---------------------------------------------------------------------------
 * Theme toggle.
 *
 * The server stamps data-theme on <html> from a cookie, but when no explicit
 * choice has been made the effective theme comes from prefers-color-scheme,
 * which only the browser knows. Resolve it here so the first click always
 * flips what the operator is actually looking at.
 * ------------------------------------------------------------------------ */

function interlockEffectiveTheme() {
    var explicit = document.documentElement.getAttribute('data-theme');
    if (explicit === 'light' || explicit === 'dark') {
        return explicit;
    }
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
}

function interlockSyncThemeInput() {
    var input = document.querySelector('.js-theme-input');
    if (input) {
        input.value = interlockEffectiveTheme() === 'dark' ? 'light' : 'dark';
    }
}

document.addEventListener('DOMContentLoaded', interlockSyncThemeInput);
document.addEventListener('click', function(event) {
    if (event.target.closest && event.target.closest('.js-theme-toggle')) {
        interlockSyncThemeInput();
    }
});

// Catalog picker: a "Use" button in the catalog tree fills the input the
// author last focused - a statement's resource pattern in the role editor, or
// the tables, columns or redact-columns list in the policy editor.
// The conditions builder writes into the row's permission_constraints JSON,
// which is the only field posted. Only keys the builder renders are touched,
// so a condition set some other way (Edit as JSON) survives.
function interlockSerializeConstraints(builder) {
    var textarea = builder.querySelector('.js-constraint-json');
    if (!textarea) return;
    var value;
    try {
        value = JSON.parse(textarea.value || '{}');
    } catch (err) {
        return; // leave text the author is still fixing alone
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    builder.querySelectorAll('.constraint-field').forEach(function(field) {
        var key = field.dataset.constraintKey;
        var kind = field.dataset.constraintType;
        delete value[key];
        if (kind === 'bool') {
            var box = field.querySelector('.js-constraint-input');
            if (box && box.checked) value[key] = true;
        } else if (kind === 'enum_list') {
            var picked = [];
            field.querySelectorAll('.js-constraint-input:checked').forEach(function(box) {
                picked.push(box.value);
            });
            if (picked.length) value[key] = picked;
        } else {
            var input = field.querySelector('.js-constraint-input');
            var items = (input ? input.value : '').split(',').map(function(item) {
                return item.trim();
            }).filter(function(item) { return item.length > 0; });
            if (items.length) value[key] = items;
        }
    });
    textarea.value = JSON.stringify(value);
}

function interlockConstraintEdited(event) {
    var target = event.target;
    if (!target.classList || !target.classList.contains('js-constraint-input')) return;
    var builder = target.closest('.constraint-builder');
    if (builder) interlockSerializeConstraints(builder);
}

document.addEventListener('input', interlockConstraintEdited);
document.addEventListener('change', interlockConstraintEdited);

var _interlockCatalogTarget = null;

document.addEventListener('focusin', function(event) {
    if (event.target.matches && event.target.matches('input[data-catalog-pick]')) {
        _interlockCatalogTarget = event.target;
    }
});

function interlockCatalogPick(button) {
    var target = _interlockCatalogTarget;
    if (!target || !document.body.contains(target)) {
        var inputs = document.querySelectorAll('input[data-catalog-pick]');
        target = inputs.length ? inputs[inputs.length - 1] : null;
    }
    if (!target) {
        return;
    }
    var kind = target.dataset.catalogPick || 'pattern';
    var value = kind === 'table' ? button.dataset.table
        : kind === 'column' ? button.dataset.column
        : button.dataset.pattern;
    if (!value) {
        return;
    }
    if (kind === 'pattern') {
        var row = target.closest('.permission-row');
        var typeSelect = row ? row.querySelector('[name="permission_resource_type"]') : null;
        var patterns = {};
        try {
            patterns = JSON.parse(button.dataset.patterns || '{}');
        } catch (err) {
            patterns = {};
        }
        var current = typeSelect ? typeSelect.value : '';
        if (patterns[current]) {
            // The row's resource type has a pattern for this node: keep it.
            target.value = patterns[current];
        } else {
            // Otherwise the pick decides what is addressed (a column is
            // db.column, an S3 prefix storage.object), if the row offers it.
            target.value = value;
            var wanted = button.dataset.resourceType;
            if (typeSelect && wanted && typeSelect.querySelector('option[value="' + wanted + '"]')) {
                typeSelect.value = wanted;
                // Re-render the row for the new type; the pattern goes with it.
                typeSelect.dispatchEvent(new Event('change', { bubbles: true }));
                return;
            }
        }
    } else {
        var parts = target.value.split(',').map(function(part) { return part.trim(); })
            .filter(function(part) { return part.length > 0; });
        if (parts.indexOf(value) === -1) {
            parts.push(value);
        }
        target.value = parts.join(', ');
    }
    target.dispatchEvent(new Event('change', { bubbles: true }));
    target.focus();
}


// Explain refused requests. htmx does not swap 4xx responses, so without this a
// read-only account clicking Save or Delete would see nothing happen.
var _interlockNoticeTimer = null;

function _interlockShowNotice(title, message) {
    var notice = document.getElementById('admin-notice');
    if (!notice) {
        return;
    }
    notice.textContent = '';
    var strong = document.createElement('strong');
    strong.textContent = title;
    notice.appendChild(strong);
    notice.appendChild(document.createTextNode(' ' + message));
    notice.hidden = false;
    if (_interlockNoticeTimer) {
        clearTimeout(_interlockNoticeTimer);
    }
    _interlockNoticeTimer = setTimeout(function() { notice.hidden = true; }, 8000);
}

function _interlockErrorText(xhr) {
    try {
        var body = JSON.parse(xhr.responseText || '{}');
        return String(body.error || body.detail || '');
    } catch (err) {
        return '';
    }
}

document.addEventListener('htmx:responseError', function(event) {
    var xhr = event.detail.xhr;
    if (!xhr) {
        return;
    }
    var error = _interlockErrorText(xhr);
    if (xhr.status === 403 && /csrf/i.test(error)) {
        _interlockShowNotice('Your session needs a refresh.', 'Reload the page and try again.');
    } else if (xhr.status === 403) {
        _interlockShowNotice("Your account can't make this change.", 'Ask an administrator if you need it.');
    } else if (xhr.status === 401) {
        _interlockShowNotice('You have been signed out.', 'Sign in again to continue.');
    } else {
        _interlockShowNotice('That did not work.', error || ('The server answered ' + xhr.status + '.'));
    }
});

document.addEventListener('htmx:sendError', function() {
    _interlockShowNotice('The console could not reach the server.', 'Check your connection and try again.');
});
