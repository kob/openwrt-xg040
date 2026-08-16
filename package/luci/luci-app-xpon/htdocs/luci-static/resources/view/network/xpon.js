'use strict';
'require form';
'require fs';
'require view';
'require ui';
'require uci';

/*
 * luci-app-xpon: Airoha EN7581 XPON PON management.
 *
 * Phase 3: surfaces the *factory-equivalent* OMCI runtime data surface.
 * The factory firmware's omciMgr writes status files into /tmp and /configs.
 * We consume those same files via a rpcd ubus backend (luci.xpon), so the page
 * renders the registration FSM, OLT messages, SLID, optical DDM, OMCI logs and
 * the data-store snapshot regardless of which PON stack is active
 * (xpon-portable kmod, Go omcid, or the original ALU omciMgr).
 *
 * Backend methods (ubus call luci.xpon <method>):
 *   status   — PON mode, registration state, authtype, slid, hardware version
 *   optical  — RX/TX power, temp, voltage, bias, LOS, SFP vendor info
 *   olt      — OLT message buffer, sw_ver, system_info, zeroman version
 *   logs     — /tmp/omci.log (tail), traces, debug-mode flag
 *   datastore — per-module data-store snapshots (TOP/OMCI/VOICE/IGMP/ETHOAM)
 *   counters — tcont_stats, gpon_counters (from xpon-portable sysfs)
 *
 * The sysfs path is read from /var/run/xpon/sysfs_path (written by init.d/xpon).
 */

var sysfsBase = null;
var ubus = null;   // ubus proxy (injected by LuCI)

function findSysfs() {
    return fs.read_direct('/var/run/xpon/sysfs_path').then(function (data) {
        if (data && data.trim())
            return data.trim();
        return null;
    }).catch(function () { return null; });
}

function readSysfs(name) {
    if (!sysfsBase)
        return Promise.resolve(null);
    return fs.read_direct(sysfsBase + '/' + name)
        .then(function (data) { return data ? data.trim() : null; })
        .catch(function () { return null; });
}

// Call the rpcd backend: returns the parsed JSON reply, or {} on failure.
function rpcCall(method) {
    return ubus.call('luci.xpon', method).then(function (reply) {
        return reply || {};
    }).catch(function (err) {
        // Backend absent (no rpcd registration) -> render empty; page still works
        // in P1/P2 mode (direct sysfs reads below).
        return {};
    });
}

// Aggregate all backend methods in parallel.
function loadRuntime() {
    return Promise.all([
        rpcCall('status'),
        rpcCall('optical'),
        rpcCall('olt'),
        rpcCall('logs'),
        rpcCall('datastore'),
        rpcCall('counters')
    ]).then(function (results) {
        return {
            status:    results[0] || {},
            optical:   results[1] || {},
            olt:       results[2] || {},
            logs:      results[3] || {},
            datastore: results[4] || {},
            counters:  results[5] || {}
        };
    });
}

// Legacy direct-sysfs read (P1/P2); kept as a fallback when the rpcd backend
// is unavailable (e.g. a stripped-down build).
function readSysfsAll() {
    return findSysfs().then(function (path) {
        sysfsBase = path;
        var names = ['onu_state', 'gpon_counters', 'tcont_stats',
                     'rx_power', 'tx_power', 'optical_temp', 'los', 'pon_link'];
        var promises = names.map(function (n) {
            return readSysfs(n).then(function (v) {
                var o = {}; o[n] = v; return o;
            });
        });
        return Promise.all(promises);
    }).then(function (results) {
        var merged = {};
        results.forEach(function (r) {
            for (var k in r) merged[k] = r[k];
        });
        return merged;
    });
}

// Human-readable ONU activation state map (GPON O1..O7).
var stateMap = {
    '0x00000001': 'O1 (standby)', '0x00000002': 'O2 (serial number)',
    '0x00000003': 'O3 (ranging)', '0x00000004': 'O4 (ranging)',
    '0x00000005': 'O5 (operational)', '0x00000006': 'O6 (popup)',
    '0x00000007': 'O7 (emergency stop)'
};

function fmtPower(val) {
    if (!val || val === 'N/A' || val === 'LOS' || val === 'null') return 'N/A';
    var n = parseInt(val, 10);
    if (isNaN(n)) return val;
    // Factory rssi_tool reports in 0.01 dBm; xpon sysfs reports raw.
    return (n / 10).toFixed(1) + ' dBm';
}

function fmtTemp(val) {
    if (!val || val === 'N/A' || val === 'null') return 'N/A';
    var n = parseInt(val, 10);
    if (isNaN(n)) return val;
    // Factory reports in milli-degrees.
    return (n / 1000).toFixed(1) + ' °C';
}

function fmtFlag(v, trueTxt, falseTxt) {
    if (v === 1 || v === '1' || v === true) return trueTxt;
    if (v === 0 || v === '0' || v === false) return falseTxt;
    return 'N/A';
}

// Render an ASCII log block inside a <pre>.
function logBlock(title, body, height) {
    if (!body || body === 'null') body = '';
    height = height || 220;
    var h = '<fieldset class="cbi-section"><legend>%s</legend>'.format(title);
    h += '<pre style="max-height:%dpx;overflow:auto;background:#f8f8f8;border:1px solid #ddd;padding:.5em;font-size:11px;white-space:pre-wrap;word-break:break-all">%s</pre>'.format(height, body.replace(/</g,'&lt;').replace(/>/g,'&gt;') || _('(empty)'));
    h += '</fieldset>';
    return h;
}

return view.extend({
    load: function () {
        // Try the rpcd backend first; fall back to direct sysfs reads.
        return loadRuntime().then(function (rt) {
            self.runtime = rt;
            // If the backend reported no sysfs path, fall back to direct read.
            if (!rt.counters || !rt.counters.sysfs_path) {
                return readSysfsAll().then(function (d) {
                    self.sysfsDirect = d;
                });
            } else {
                sysfsBase = rt.counters.sysfs_path;
                self.sysfsDirect = null;
            }
        });
    },

    render: function () {
        var m, s, o;
        var rt = self.runtime || {};
        var st = rt.status || {};
        var opt = rt.optical || {};
        var olt = rt.olt || {};
        var logs = rt.logs || {};
        var ds = rt.datastore || {};
        var cnt = rt.counters || {};

        // Merge direct-sysfs fallback into counters/sysfs view.
        var sf = self.sysfsDirect || {};
        if (!cnt.tcont_stats && sf.tcont_stats) cnt.tcont_stats = sf.tcont_stats;
        if (!cnt.gpon_counters && sf.gpon_counters) cnt.gpon_counters = sf.gpon_counters;

        m = new form.Map('xpon', _('PON / XPON Configuration'),
            _('Configure the ONU serial number, password and PON protocol mode. ' +
              'After saving, click "Apply" to reload the xpon driver and restart omcid. ' +
              'The lower panels show live factory-equivalent OMCI runtime status.'));

        // Inject ubus proxy reference (LuCI provides ubus on the view context).
        if (this.bus && this.bus.call) ubus = this.bus;
        else if (typeof ubus !== 'undefined' && ubus && ubus.call) {
            // already injected via 'require uci'/'require ubus'
        } else {
            // Fallback: use the global ubus module loaded via 'require ubus'
            // (LuCI exposes L.ubus in client-side builds).
            try { ubus = L.ubus || window.ubus; } catch (e) {}
        }

        // =====================================================================
        // Section 1 — Settings (existing P1/P2 config)
        // =====================================================================
        s = m.section(form.TypedSection, 'xpon', _('Settings'));
        s.addremove = false;
        s.anonymous = true;

        o = s.option(form.ListValue, 'pon_mode', _('PON Mode'));
        o.value('0', _('GPON (1.25G / 2.5G)'));
        o.value('1', _('EPON (1G)'));
        o.value('2', _('XGS-PON (10G symmetric)'));
        o.value('3', _('10G-EPON (XEPON)'));
        o.default = '0';
        o.description = _('The PON protocol mode. Must match the OLT configuration. ' +
                         'GPON is the default for XG-040G-MD on most carrier networks.');

        o = s.option(form.Value, 'sn', _('ONU Serial Number'),
            _('Format: 4 vendor chars + 4 hex digits (e.g. ALCL12345678). ' +
              'Leave empty to use the factory-programmed SN.'));
        o.datatype = 'string';
        o.placeholder = 'ALCL00000000';
        o.maxlength = 16;

        o = s.option(form.Value, 'password', _('GPON Password / LOID'),
            _('Up to 10 ASCII characters. Leave empty if the OLT uses SN-only authentication.'));
        o.datatype = 'string';
        o.maxlength = 10;
        o.password = true;

        o = s.option(form.Value, 'epon_onu_mac', _('EPON ONU MAC'),
            _('MAC address for EPON/XEPON LLID registration (AA:BB:CC:DD:EE:FF). ' +
              'Only used in EPON mode. Leave empty to use device-tree value.'));
        o.datatype = 'macaddr';
        o.depends('pon_mode', '1');
        o.depends('pon_mode', '3');

        // =====================================================================
        // Section 2 — Live Status (P3 runtime view)
        // =====================================================================
        var html = '<div class="cbi-section-node">';

        // ---- 2.1 PON mode & registration FSM ----
        html += '<h3>%s</h3>'.format(_('PON Mode & Registration FSM'));

        var modeStr = st.uplink || sf.onu_state || '—';
        html += '<p><strong>%s:</strong> %s'.format(_('Active PON Mode'), String(modeStr).toUpperCase());
        if (st.sysponmode) html += ' &nbsp; <strong>%s:</strong> %s'.format(_('System PON'), st.sysponmode);
        if (st.lanmode)   html += ' &nbsp; <strong>%s:</strong> %s'.format(_('LAN Mode'), st.lanmode);
        html += '</p>';

        // Activation state (from xpon-portable sysfs or /tmp/omci.log parsing).
        var actState = st.onu_state || '';
        var stateDesc = stateMap[actState] || (actState || _('unknown'));
        html += '<p><strong>%s:</strong> %s'.format(_('ONU Activation State'), stateDesc);
        if (st.reg_state !== null && st.reg_state !== undefined) {
            html += ' &nbsp; <strong>%s:</strong> %s'.format(_('Registered'),
                fmtFlag(st.reg_state, _('YES'), _('NO')));
        }
        if (st.reg_times !== null && st.reg_times !== undefined) {
            html += ' &nbsp; <strong>%s:</strong> %s'.format(_('Attempts'), st.reg_times);
        }
        html += '</p>';

        // Auth type & vendor.
        html += '<p><strong>%s:</strong> %s &nbsp; <strong>%s:</strong> %s</p>'.format(
            _('Authentication Type'), (st.authtype || _('N/A')),
            _('Vendor ID'), (st.vendor || _('N/A')));

        // PON connection state & uptime.
        html += '<p><strong>%s:</strong> %s'.format(_('PON Connection'),
            fmtFlag(st.pon_conn, _('UP'), _('DOWN')));
        if (st.pon_uptime) {
            var up = parseInt(st.pon_uptime, 10);
            if (!isNaN(up)) {
                var mins = Math.floor(up/60), secs = up%60;
                html += ' &nbsp; <strong>%s:</strong> %dm %ds'.format(_('Uptime'), mins, secs);
            }
        }
        html += '</p>';

        // SLID.
        if (st.slid) {
            html += '<p><strong>%s:</strong> %s</p>'.format(_('SLID'), st.slid);
        }

        // Failure flags.
        var flags = [];
        if (st.loid_failure == 1) flags.push(_('LOID auth failed'));
        if (st.pwd_failure  == 1) flags.push(_('Password auth failed'));
        if (st.pon_down      == 1) flags.push(_('PON down'));
        if (st.error_slid    == 1) flags.push(_('SLID error'));
        if (st.pon_disabled  == 1) flags.push(_('PON disabled (O7 emergency)'));
        if (st.ploam_on      == 1) flags.push(_('PLOAM enabled'));
        html += '<p><strong>%s:</strong> %s</p>'.format(_('Flags'),
            flags.length ? flags.join(', ') : _('none'));

        if (st.hardware_version) {
            html += '<p><strong>%s:</strong> %s</p>'.format(_('Hardware Version'), st.hardware_version);
        }

        // ---- 2.2 Optical monitoring (DDM) ----
        html += '<h3>%s</h3>'.format(_('Optical Monitoring (DDM)'));

        var losColor = (opt.los == 1 || opt.los == '1') ? 'red' : 'green';
        var losText  = (opt.los == 1 || opt.los == '1') ? _('ALARM (signal lost)') : _('OK');
        html += '<p><strong>%s:</strong> <span style="color:%s">%s</span></p>'.format(
            _('LOS (Loss of Signal)'), losColor, losText);

        html += '<p><strong>%s:</strong> %s &nbsp; <strong>%s:</strong> %s</p>'.format(
            _('RX Power'), fmtPower(opt.rx_power),
            _('TX Power'), fmtPower(opt.tx_power));
        if (opt.temperature) {
            html += '<p><strong>%s:</strong> %s &nbsp; <strong>%s:</strong> %s &nbsp; <strong>%s:</strong> %s</p>'.format(
                _('Module Temp'), fmtTemp(opt.temperature),
                _('Bias Current'), opt.bias_current || 'N/A',
                _('Voltage'), opt.voltage || 'N/A');
        }
        if (opt.txpower_error == 1) {
            html += '<p><span style="color:red">%s</span></p>'.format(_('TX power error flag set'));
        }
        if (opt.vendor_name || opt.vendor_pn || opt.vendor_sn || opt.opt_sn) {
            html += '<p><strong>%s:</strong> %s &nbsp; <strong>%s:</strong> %s &nbsp; <strong>%s:</strong> %s</p>'.format(
                _('SFP Vendor'), opt.vendor_name || 'N/A',
                _('Part No.'), opt.vendor_pn || 'N/A',
                _('Serial No.'), opt.vendor_sn || opt.opt_sn || 'N/A');
        }

        // ---- 2.3 OLT information ----
        html += '<h3>%s</h3>'.format(_('OLT Information'));
        if (olt.sw_ver) {
            html += '<p><strong>%s:</strong> %s</p>'.format(_('Software Version'), olt.sw_ver);
        }
        if (olt.zeroman_version) {
            html += '<p><strong>%s:</strong> %s</p>'.format(_('Zero-Man Version'), olt.zeroman_version);
        }
        if (olt.oltmsg && olt.oltmsg !== 'null') {
            html += logBlock(_('OLT Messages (last 8 lines)'), olt.oltmsg, 140);
        }

        // ---- 2.4 Hardware counters & TCONT (xpon-portable sysfs) ----
        html += '<h3>%s</h3>'.format(_('GPON MAC Hardware Counters'));
        var counters = String(cnt.gpon_counters || '').split('\n').filter(Boolean);
        if (counters.length === 0) {
            html += '<p>%s</p>'.format(_('No counter data available.'));
        } else {
            html += '<table class="table"><tbody>';
            counters.forEach(function (line) {
                var parts = line.split('=');
                if (parts.length === 2) {
                    html += '<tr><td style="width:50%%">%s</td><td>%s</td></tr>'.format(
                        parts[0], parts[1]);
                }
            });
            html += '</tbody></table>';
        }

        html += '<h3>%s</h3>'.format(_('T-CONT / Alloc-ID Table'));
        var tconts = String(cnt.tcont_stats || '').split('\n').filter(Boolean);
        if (tconts.length === 0) {
            html += '<p>%s</p>'.format(_('No TCONT data available.'));
        } else {
            html += '<table class="table"><thead><tr><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>'.format(
                _('T-CONT'), _('Alloc-ID'), _('Valid'));
            tconts.forEach(function (line) {
                var mt = line.match(/tcont(\d+): alloc_id=(\d+) valid=(\d+)/);
                if (mt) {
                    html += '<tr><td>%d</td><td>%s</td><td>%s</td></tr>'.format(
                        parseInt(mt[1], 10), mt[2], mt[3] === '1' ? '✓' : '—');
                }
            });
            html += '</tbody></table>';
        }

        // ---- 2.5 OMCI logs & traces ----
        html += '<h3>%s</h3>'.format(_('OMCI Protocol Logs'));
        if (logs.debug_mode == 1) {
            html += '<p><span style="color:orange">%s</span></p>'.format(_('OMCI debug mode is ON'));
        }
        if (logs.omci_log && logs.omci_log !== 'null') {
            html += logBlock(_('/tmp/omci.log (last 30 lines)'), logs.omci_log, 240);
        } else {
            html += '<p>%s</p>'.format(_('No OMCI log available.'));
        }
        if (logs.omcimgr_trace && logs.omcimgr_trace !== 'null') {
            html += logBlock(_('omciMgr Trace'), logs.omcimgr_trace, 180);
        }
        if (logs.parser_trace && logs.parser_trace !== 'null') {
            html += logBlock(_('Parser Trace'), logs.parser_trace, 180);
        }
        if (logs.ploam_trace && logs.ploam_trace !== 'null') {
            html += logBlock(_('PLOAM Trace'), logs.ploam_trace, 180);
        }

        // ---- 2.6 Data-store snapshots ----
        if (ds.in_progress == 1) {
            html += '<p><span style="color:blue">%s</span></p>'.format(_('Data store in progress'));
        }
        if (ds.top && ds.top !== 'null') {
            html += logBlock(_('Data-store: TOP'), ds.top, 120);
        }
        if (ds.omci && ds.omci !== 'null') {
            html += logBlock(_('Data-store: OMCI'), ds.omci, 120);
        }
        if (ds.voice && ds.voice !== 'null') {
            html += logBlock(_('Data-store: VOICE'), ds.voice, 120);
        }
        if (ds.igmp && ds.igmp !== 'null') {
            html += logBlock(_('Data-store: IGMP'), ds.igmp, 120);
        }
        if (ds.ethoam && ds.ethoam !== 'null') {
            html += logBlock(_('Data-store: ETHOAM'), ds.ethoam, 120);
        }

        html += '</div>';

        var monField = s.option(form.DummyValue, '_monitoring', _('Live Status (factory-equivalent OMCI runtime)'));
        monField.rawhtml = true;
        monField.default = html;

        return m.render();
    },

    // Poll monitoring data every 5 seconds for live updates.
    handleSaveApply: function (ev, mode) {
        return this.super('handleSaveApply', [ev, mode]).then(function () {
            // After apply, the driver reloads; trigger a page reload after a delay.
            setTimeout(function () { location.reload(); }, 3000);
        });
    }
});
