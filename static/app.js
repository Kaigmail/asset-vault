'use strict';

/* ================= 状态 ================= */
const TOKEN_KEY = 'vault_token';       // 会话 token（非敏感字段明文，唯一允许落 localStorage 的键）

const state = {
  token: null,
  view: 'assets',
  cat: 'all',
  q: '',
  assets: [],     // 全量资产（列表接口，敏感字段为掩码）
  cats: [],       // 分类
  results: [],    // 当前展示的资产
  reqs: [],       // 待审批列表
  editAssetId: null,
  vaultState: null,   // /api/vault/state 的库格式状态
  backupStatus: null, // /api/backup/status 结果
  approvalHistory: [], // 已处理审批的非敏感记录
  backupHistory: [],   // 受管备份包清单
  backupHistoryShown: 10, // 备份记录默认展示条数
  // US4：AI 总开关与上云提示偏好，权威在服务端 data/settings.json；只留内存镜像，不写 localStorage
  aiSettings: { aiEnabled: false, riskPromptSuppressed: false },
};

// 副本升级向导状态（源密码只在内存，关闭即清）
let migrationSources = null;  // GET /api/migration/sources 结果
let upgradeOp = null;         // prepare 返回的操作信息
let upgradeSource = null;     // 当前选中的副本标识
let upgradeStep = 1;
let upgradeCountdown = null;
let legacyFile = null;        // 待转换的旧材料文件（仅内存引用）

// 恢复向导状态（密码/文件只在内存，不写 localStorage）
let restoreFile = null;         // 用户选择的备份文件
let restoreOp = null;           // prepare 返回的操作信息
let restoreMode = null;         // 'empty'（空环境凭证）| 'replace'（已有库会话）
let restoreStep = 1;
let restoreCountdown = null;

let editFields = [];      // 模态框字段编辑态（关闭即清空）
let editCats = [];
let originalCats = [];
let unlockMode = 'login';
let searchTimer = null;
let sessionInvalidShown = false;  // 会话失效回解锁页只提示一次

const $ = (id) => document.getElementById(id);

/* ================= 通用工具 ================= */
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
function maskSecret() { return '••••••••••'; }
function toast(msg, isErr) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.toggle('error', !!isErr);
  el.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), 2600);
}
function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso).slice(0, 16).replace('T', ' ');
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function statusInfo(s) {
  return { normal: ['s-normal', '正常'], expiring: ['s-expiring', '临期'], expired: ['s-expired', '过期'], disabled: ['s-disabled', '未启用'] }[s] || ['s-normal', '正常'];
}
function riskInfo(r) {
  return { high: ['#e5484d', '高风险'], mid: ['#e8a23d', '中风险'], low: ['#22a06b', '低风险'] }[r] || ['#8a919c', '未标'];
}
function catName(key) {
  const c = state.cats.find((x) => x.key === key);
  return c ? c.name : '未分类';
}
function assetName(id) {
  const a = state.assets.find((x) => String(x.id) === String(id));
  return a ? a.name : '#' + id;
}

/* ================= API 封装 ================= */
/* FR-018 限流话术（US6/T038，BACKLOG D1）：仅 maintenance_rate_limited 一个码命中。
   安全限流机制（阈值/窗口）全在后端 app/operations.py，前端只翻译话术，
   不放宽、不重试、不复制任何阈值；其余错误码一律沿用后端脱敏短语。 */
const RATE_LIMIT_CODE = 'maintenance_rate_limited';
const RATE_LIMIT_TEXT = '操作过于频繁，请约 5 分钟后再试（或重启程序）';
/* US4：AI 总开关关闭时后端以 403 ai_disabled 拒绝写入口，前端统一翻译为人话（FR-015） */
const AI_DISABLED_CODE = 'ai_disabled';
const AI_DISABLED_TEXT = 'AI 功能未开启：请先在「设置 → AI 辅助设置」中开启总开关';
function errorMessage(data, res) {
  if (data && data.code === RATE_LIMIT_CODE) return RATE_LIMIT_TEXT;
  if (data && data.code === AI_DISABLED_CODE) return AI_DISABLED_TEXT;
  return (data && data.error) || '请求失败（' + res.status + '）';
}
/* 桌面运行时通道凭证（T020）：
 * 桌面外壳在页面 loaded 后经 evaluate_js 注入 window.__AV_DESKTOP__ = { token }；
 * 浏览器开发入口（start.bat）永远没有该标志。每次请求时读取，避开页面脚本先于
 * 注入执行的时序；凭证只存 JS 内存，刷新由外壳重新注入，不写 localStorage/sessionStorage。 */
function desktopChannelToken() {
  const d = window.__AV_DESKTOP__;
  return d && typeof d.token === 'string' ? d.token : null;
}
function withDesktopChannel(path, init) {
  const token = desktopChannelToken();
  if (!token) return init;  // 浏览器入口：原样返回，行为零变化
  // 仅同源 /api/ 补头：相对路径与同源绝对路径都算，外域/非接口路径一律不碰
  const isSameOriginApi = path.indexOf('/api/') === 0 ||
    path.indexOf(window.location.origin + '/api/') === 0;
  if (!isSameOriginApi) return init;
  const headers = Object.assign({}, (init && init.headers) || {});
  if (!headers['X-Channel-Token']) headers['X-Channel-Token'] = token;  // 不覆盖既有头
  return Object.assign({}, init, { headers });
}
function desktopFetch(path, init) {
  // 全文件唯一的 native fetch 收口：所有请求都经通道包装后再发出
  return fetch(path, withDesktopChannel(path, init));
}
async function api(path, options = {}) {
  const headers = Object.assign({ Accept: 'application/json' }, options.headers || {});
  if (state.token) headers.Authorization = 'Bearer ' + state.token;
  let body = options.body;
  if (body !== undefined && !(body instanceof FormData) && typeof body !== 'string') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  let res;
  try {
    res = await desktopFetch(path, Object.assign({}, options, { headers, body }));
  } catch (err) {
    throw new Error('无法连接后端服务，请确认服务已启动');
  }
  let data = null;
  try { data = await res.json(); } catch (err) { /* 非 JSON 响应 */ }
  if (!res.ok) {
    // 后端 OperationError 的错误码在 code 字段（error 为脱敏中文短语）；
    // 限流码在 errorMessage() 唯一收口翻译为人话（FR-018），其余码沿用后端短语
    const e = new Error(errorMessage(data, res));
    e.code = data && data.code;
    e.status = res.status;
    // 会话级失效统一清场：用户会话 401，或库锁定后任意写/读拿到 423 vault_locked。
    // 不带 token 的请求（解锁前）不触发；网络错误不进这里，init 仍可保留 token 等待后端恢复。
    if (state.token && !options.skipSessionGuard && (res.status === 401 ||
        (res.status === 423 && e.code === 'vault_locked'))) {
      handleSessionInvalid(res.status === 423).catch(() => {});
    }
    throw e;
  }
  return data;
}
function errCode(err) { return (err && err.code) || ''; }

/* ================= 解锁 / 锁定 ================= */
const pinBoxes = [...document.querySelectorAll('.pin-box')];

function resetPin() {
  pinBoxes.forEach((b) => { b.value = ''; b.classList.remove('filled'); });
  pinBoxes[0].focus();
}
function setUnlockMode(mode) {
  unlockMode = mode;
  const sub = $('unlock-sub'), banner = $('unlock-banner'), btn = $('unlock-btn'), link = $('restore-entry-link');
  if (mode === 'create') {
    sub.textContent = '创建主密码：输入 6 位数字（请抄写到安全处，丢失无法恢复）';
    banner.innerHTML = '<div class="warn-banner">⚠️ 主密码是唯一钥匙，忘记后将无法解密任何数据。请务必抄写到安全处。也可以不从备份恢复。</div>';
    banner.classList.remove('hidden');
    btn.textContent = '创建新密码库并进入';
    link.classList.remove('hidden');
  } else if (mode === 'setup') {
    sub.textContent = '设置主密码：输入 6 位数字（请抄写到安全处，丢失无法恢复）';
    banner.innerHTML = '<div class="warn-banner">⚠️ 主密码是唯一钥匙，忘记后将无法解密任何数据。请务必抄写到安全处。</div>';
    banner.classList.remove('hidden');
    btn.textContent = '设置主密码并进入';
    link.classList.add('hidden');
  } else if (mode === 'saved') {
    sub.textContent = '主密码设置成功：请抄写到安全处，丢失无法恢复';
    banner.innerHTML = '<div class="warn-banner">⚠️ 请确认已将主密码抄写到安全处。本工具无法找回主密码，忘记即数据永久丢失。</div>';
    banner.classList.remove('hidden');
    btn.textContent = '我已抄写，进入保险库';
    link.classList.add('hidden');
  } else if (mode === 'blocked') {
    // 未知/损坏库：不展示首次空库，也不提供输入入口
    sub.textContent = '暂时无法打开这个库';
    banner.classList.add('hidden');
    btn.textContent = '解锁';
    link.classList.add('hidden');
  } else {
    sub.textContent = '输入主密码解锁（6 位数字）';
    banner.classList.add('hidden');
    banner.innerHTML = '';
    btn.textContent = '解锁';
    link.classList.add('hidden');
  }
}

async function tryUnlock() {
  if (unlockMode === 'blocked') return; // 损坏/未知库拒绝输入
  const code = pinBoxes.map((b) => b.value).join('');
  if (code.length < 6) { $('unlock-err').textContent = '请输入 6 位数字'; return; }
  $('unlock-err').textContent = '';
  $('unlock-btn').disabled = true;
  try {
    const body = { password: code };
    if (unlockMode === 'create') body.initialize = true; // 显式创建，空/缺失库才允许初始化
    const data = await api('/api/unlock', { method: 'POST', body });
    state.token = data.token;
    localStorage.setItem(TOKEN_KEY, data.token);
    if (data.first_run) {
      setUnlockMode('saved');
      resetPin();
    } else {
      enterApp();
    }
  } catch (err) {
    $('unlock-err').textContent = errCode(err) === 'invalid_identity_or_credentials'
      ? '主密码错误' : ('解锁失败：' + err.message);
  } finally {
    $('unlock-btn').disabled = false;
  }
}

function handleUnlockClick() {
  if (unlockMode === 'saved') { enterApp(); return; }
  tryUnlock();
}

function isLegacyReadonly() {
  return !!(state.vaultState && state.vaultState.state === 'legacy_read_only');
}

function enterApp() {
  sessionInvalidShown = false;  // 新会话开始，允许下一次失效再提示
  $('unlock').classList.add('hidden');
  $('app').classList.remove('hidden');
  document.body.classList.toggle('legacy-readonly', isLegacyReadonly());
  $('session-state-note').textContent = isLegacyReadonly()
    ? '旧版只读 · 副本升级后可用 AI 审批'
    : '已解锁 · 闲置 15 分钟锁定';
  setUnlockMode('login');
  resetPin();
  armIdleWatch();
  refreshAll();
}

/* 敏感界面清场（US4 T055）：令牌、列表、明文、弹窗与密码输入全部从 DOM/内存移除。
   待审批是服务端保留的密文数据，这里不做任何前端删除，重新解锁刷新即可再见。 */
const SENSITIVE_MODALS = ['asset-modal', 'cat-modal', 'restore-modal', 'upgrade-modal',
  'legacy-info-modal', 'rollback-modal', 'wipe-modal', 'pwd-change-modal', 'ai-risk-modal'];
function clearSensitiveSurface() {
  const pendingKept = state.reqs.length;   // 供解锁页提示「N 项待审批已保留」
  state.token = null;
  localStorage.removeItem(TOKEN_KEY);
  state.assets = []; state.cats = []; state.results = []; state.reqs = [];
  state.cat = 'all'; state.q = ''; state.editAssetId = null; state.backupStatus = null;
  editFields = []; editCats = []; originalCats = [];
  // 向导只在内存保存的密码/文件引用一并释放
  restoreFile = null; restoreOp = null; restoreMode = null; restoreStep = 1;
  clearInterval(restoreCountdown); restoreCountdown = null;
  upgradeOp = null; upgradeSource = null; upgradeStep = 1; migrationSources = null;
  clearTimeout(upgradeCountdown); upgradeCountdown = null;
  legacyFile = null;
  // 关闭所有敏感弹窗（点锁定/会话失效时，编辑与确认输入不留屏）
  SENSITIVE_MODALS.forEach((id) => { const el = $(id); if (el) el.classList.add('hidden'); });
  // 改密弹窗位于 #app 之外，三个密码输入不受下方 #app 选择器覆盖，需显式清空
  ['pwd-current', 'pwd-new', 'pwd-confirm'].forEach((id) => { const f = $(id); if (f) f.value = ''; });
  // AI 风险确认弹窗复位：勾选不留屏，确认键回到禁用门禁
  ['ai-risk-confirm', 'ai-risk-suppress'].forEach((id) => { const f = $(id); if (f) f.checked = false; });
  const aiRiskBtn = $('ai-risk-confirm-btn');
  if (aiRiskBtn) aiRiskBtn.disabled = true;
  const fieldEditor = $('field-editor');
  if (fieldEditor) fieldEditor.innerHTML = '';
  const search = $('search');
  if (search) search.value = '';
  // 弹窗内三类源/恢复密码输入框（解锁页 PIN 由 resetPin 清）
  document.querySelectorAll('#app input[type=password]').forEach((i) => { i.value = ''; });
  // AI 令牌显示还原为占位，不把旧令牌留在 DOM
  const tokenBox = $('ai-token');
  if (tokenBox) tokenBox.textContent = '—';
  // 重渲染为空：移除列表中已揭示的明文与审批预览（含敏感字段表格）
  renderList();
  renderReqs();
  stopIdleWatch();
  return pendingKept;
}

/* 回到解锁页并按库状态呈现；message 为锁定/失效原因（对照原型 08 的提示条） */
async function returnToUnlock(message) {
  const pendingKept = clearSensitiveSurface();
  $('app').classList.add('hidden');
  $('unlock').classList.remove('hidden');
  document.body.classList.remove('legacy-readonly');
  await loadVaultState();          // 重新按库状态呈现解锁页
  applyVaultStateToUnlock(state.vaultState);
  // 首启两入口页接管呈现（如删库成功后）：解锁卡隐藏，不再覆盖其 banner
  if (isFirstRunState(state.vaultState)) { resetPin(); return; }
  // 损坏/冻结等封锁态保留其专属文案与输入封锁；正常锁定态再覆盖原因提示
  if (!$('pin-row').classList.contains('hidden')) {
    const kept = pendingKept > 0 ? `${pendingKept} 项待审批已保留。` : '';
    $('unlock-banner').innerHTML =
      `<div class="warn-banner">${esc(message)}${kept ? '<br>' + esc(kept) : ''
       }锁定期间 AI 请求会被拒绝、不排队，解锁后由 AI 重新提交。</div>`;
    $('unlock-banner').classList.remove('hidden');
  }
  resetPin();
}

async function lockApp() {
  // 本接口无论成功还是会话已过期，都由 lockApp 自己清场，跳过 api() 的失效守卫避免重复提示
  try { await api('/api/lock', { method: 'POST', skipSessionGuard: true }); } catch (err) { /* 忽略 */ }
  await returnToUnlock('密码库已锁定，敏感内容已隐藏。');
}

/* 强制重新解锁：恢复/换代提交后所有会话已失效（message 为绿色成功语义，单独保留样式） */
async function forceRelock(message) {
  const pendingKept = clearSensitiveSurface();
  $('app').classList.add('hidden');
  $('unlock').classList.remove('hidden');
  document.body.classList.remove('legacy-readonly');
  await loadVaultState();
  applyVaultStateToUnlock(state.vaultState);
  if (!$('pin-row').classList.contains('hidden')) {
    $('unlock-banner').innerHTML = `<div class="warn-banner">✅ ${esc(message)}</div>`;
    $('unlock-banner').classList.remove('hidden');
  }
  resetPin();
}

/* 会话被动失效（401/423）：只在首次触发时清场一次，并发失败请求不重复弹提示 */
async function handleSessionInvalid(locked) {
  if (sessionInvalidShown) return;
  sessionInvalidShown = true;
  const message = locked
    ? '密码库已锁定（可能在别处锁定、程序重启，或闲置超过 15 分钟），敏感内容已隐藏。'
    : '登录会话已失效，敏感内容已隐藏。';
  await returnToUnlock(message);
}

/* 前端闲置看护：与后端 15 分钟闲置过期对齐。只有浏览器内用户操作续期；
   AI 请求不经过本页面（且后端也不为 AI 续期）。到期只清本地界面，
   不调 /api/lock——后端会话此刻同样已过期，且锁定操作会影响其他会话。 */
const IDLE_LIMIT_MS = 15 * 60 * 1000;
let idleTimer = null;
function armIdleWatch() {
  if (!state.token) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(onIdleExpired, IDLE_LIMIT_MS);
}
function stopIdleWatch() {
  clearTimeout(idleTimer);
  idleTimer = null;
}
function onIdleExpired() {
  idleTimer = null;
  if (!state.token) return;
  toast('闲置超过 15 分钟，已自动锁定');
  handleSessionInvalid(true).catch(() => {});
}
document.addEventListener('click', armIdleWatch, true);
document.addEventListener('keydown', armIdleWatch, true);

/* ================= 数据加载 ================= */
async function loadAssets() {
  try {
    state.assets = await api('/api/assets');
    if (!state.q) state.results = state.assets;
  } catch (err) {
    toast('加载资产失败：' + err.message, true);
  }
}
async function loadCats() {
  try {
    state.cats = await api('/api/categories');
  } catch (err) {
    toast('加载分类失败：' + err.message, true);
  }
}
async function loadApprovals() {
  try {
    state.reqs = await api('/api/approvals');
    renderReqs();
  } catch (err) {
    toast('加载审批失败：' + err.message, true);
  }
}
async function loadToken() {
  try {
    const data = await api('/api/token');
    $('ai-token').textContent = data.ai_token || '';
  } catch (err) {
    toast('加载令牌失败：' + err.message, true);
  }
}
async function refreshAll() {
  // 旧版只读库的审批/令牌域由后端以 409 vault_read_only 关闭，前端不发起这些请求
  if (isLegacyReadonly()) {
    state.reqs = [];
    await Promise.all([loadAssets(), loadCats()]);
    renderReqs();
  } else {
    // 审批历史须随批准/拒绝即时刷新，否则用户处理后看不到刚落账的非敏感记录
    await Promise.all([loadAssets(), loadCats(), loadApprovals(), loadApprovalHistory()]);
  }
  if (state.q) await doSearch(); else renderList();
  renderNav();
}

/* ================= 资产列表渲染 ================= */
function renderNav() {
  const counts = {};
  state.assets.forEach((a) => { counts[a.category_key] = (counts[a.category_key] || 0) + 1; });
  counts.all = state.assets.length;
  const items = [{ key: 'all', name: '全部资产', icon: '🗂️' }].concat(state.cats);
  $('nav').innerHTML = items.map((c) => `
    <div class="nav-item ${state.cat === c.key ? 'active' : ''}" data-cat="${esc(c.key)}">
      <span class="ico">${esc(c.icon)}</span><span class="label">${esc(c.name)}</span><span class="count">${counts[c.key] || 0}</span>
    </div>`).join('');
}

/* ================= US5：优先级与到期日（纯前端动态计算，零落库） =================
 * 分组/排序只在渲染时按本机当天计算：后端不存分组、无派生列，
 * 绝不回写 priority/status/risk；30 天阈值只收口在 DUE_SOON_DAYS 一处。 */
const DUE_SOON_DAYS = 30;

// 严格解析 YYYY-MM-DD 纯日期：正则收口格式，再用 Date 做真实日历校验（闰年/月份天数）
function parseDateOnly(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  if (dt.getFullYear() !== y || dt.getMonth() !== m - 1 || dt.getDate() !== d) return null;
  return dt;
}

// 距 today 的整数天差：当天为 0、过去为负；空值/非法值返回 null
function daysUntil(s, today) {
  const due = parseDateOnly(s);
  if (!due) return null;
  const t = today || new Date();
  const base = new Date(t.getFullYear(), t.getMonth(), t.getDate());
  return Math.round((due.getTime() - base.getTime()) / 86400000);
}

// 五组编号：0 过期（严格早于当天）/ 1 临期（当天起 30 天内，当天计 0 天）/
// 2 手动高 / 3 普通 / 4 低；有到期日时动态分组覆盖手动档位，清空即退回手动组
function dueGroup(a, today) {
  const d = daysUntil(a.due_date, today);
  if (d !== null && d < 0) return 0;
  if (d !== null && d <= DUE_SOON_DAYS) return 1;
  if (a.priority === 'high') return 2;
  if (a.priority === 'low') return 4;
  return 3;
}

// 纯计算排序：返回新数组，不改原数组、不发任何请求；三列表共用这唯一收口
function sortAssets(list, today) {
  return list.slice().sort((x, y) => {
    const gx = dueGroup(x, today);
    const gy = dueGroup(y, today);
    if (gx !== gy) return gx - gy;
    if (gx === 0 || gx === 1) {
      // 过期/临期组内统一按到期日近远：日期越早越靠前
      const dx = daysUntil(x.due_date, today);
      const dy = daysUntil(y.due_date, today);
      if (dx !== dy) return dx - dy;
    }
    return x.id - y.id;  // 同组同日期或无日期：按 id 稳定，刷新不跳动
  });
}

// 卡片到期标识：过期红 / 临期琥珀 / 当天专属文案；无日期与远期返回 null
function dueBadge(a, today) {
  const d = daysUntil(a.due_date, today);
  if (d === null) return null;
  if (d < 0) return { kind: 'overdue', text: `已过期 · 剩 ${d} 天` };
  if (d <= DUE_SOON_DAYS) {
    return { kind: 'due-soon', text: `${d === 0 ? '今天到期' : '临期'} · 剩 ${d} 天` };
  }
  return null;
}

function renderList() {
  const today = new Date();  // 本机当天；动态值只参与本次渲染，绝不落库
  const filtered = sortAssets(
    state.results.filter((a) => state.cat === 'all' || a.category_key === state.cat),
    today,
  );
  $('total').textContent = filtered.length;
  $('list').innerHTML = filtered.length
    ? filtered.map((a) => cardHTML(a, today)).join('')
    : '<div class="empty">没有匹配的资产</div>';
}

function fieldChip(f) {
  const v = f.sensitive ? maskSecret() : f.value;
  return `<span class="chip"><span class="k">${esc(f.label)}</span><span class="v">${esc(v)}</span></span>`;
}

function fieldHTML(aid, f, idx) {
  if (f.sensitive) {
    const secId = 'sec-' + aid + '-' + idx;
    return `<div class="field-row"><span class="fl">${esc(f.label)} <span class="secret-badge">🔒敏感</span></span>
      <span class="fv"><span class="mono-secret" id="${secId}">${maskSecret()}</span>
      <button class="eye" data-aid="${aid}" data-fidx="${idx}" data-sec="${secId}">👁</button>
      <button class="copy" data-aid="${aid}" data-fidx="${idx}" data-sec="${secId}">复制</button></span></div>`;
  }
  if (f.kind === 'url') {
    const href = /^https?:\/\//i.test(String(f.value)) ? String(f.value) : '';
    const text = href || String(f.value || '');
    return `<div class="field-row"><span class="fl">${esc(f.label)}</span><span class="fv"><a href="${esc(href)}" target="_blank" rel="noopener">${esc(text)}</a><button class="copy" data-txt="${esc(text)}">复制</button></span></div>`;
  }
  if (f.kind === 'note') {
    return `<div class="field-row"><span class="fl">${esc(f.label)}</span><span class="fv note">${esc(f.value)}</span></div>`;
  }
  return `<div class="field-row"><span class="fl">${esc(f.label)}</span><span class="fv"><span class="fv-text">${esc(f.value)}</span><button class="copy" data-txt="${esc(f.value)}">复制</button></span></div>`;
}

function cardHTML(a, today) {
  const st = statusInfo(a.status);
  const rk = riskInfo(a.risk);
  const fields = a.fields || [];
  const deps = (a.depends_on || []).map(assetName);
  // US5：到期标识按本机当天动态生成；无到期日不渲染任何到期元素（含类名/文案）
  const badge = dueBadge(a, today);
  const dueLine = badge
    ? `<div class="due-row"><span class="due-tag ${badge.kind}">${esc(badge.text)}</span><span class="due-date">到期日 ${esc(a.due_date)}</span></div>`
    : '';
  return `<div class="card ${badge ? 'card-' + badge.kind : ''}" data-id="${a.id}">
    <div class="card-head">
      <div class="card-ico">${esc(a.icon || '🏷️')}</div>
      <div class="card-title">
        <div class="name">${esc(a.name)}${a.provider ? `<span class="tag">${esc(a.provider)}</span>` : ''}</div>
        <div class="meta">${esc(catName(a.category_key))} · <span style="color:${rk[0]}">${rk[1]}</span></div>
      </div>
      <span class="status-dot ${st[0]}"></span><span class="status-label">${st[1]}</span>
    </div>
    <div class="card-tags">${(a.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</div>
    ${dueLine}
    <div class="card-summary">${fields.slice(0, 3).map(fieldChip).join('')}</div>
    <div class="detail">
      ${fields.map((f, i) => fieldHTML(a.id, f, i)).join('')}
      ${deps.length ? `<div class="field-row"><span class="fl">🔗 关联依赖</span><span class="fv note">${deps.map((d) => `<span class="tag">${esc(d)}</span>`).join(' ')}</span></div>` : ''}
      <div class="field-row detail-actions">
        <button class="btn-ghost edit-btn" data-aid="${a.id}">✏️ 编辑</button>
        <button class="btn-ghost del-btn" data-aid="${a.id}">🗑️ 删除</button>
      </div>
    </div>
  </div>`;
}

/* 敏感字段：只在点 👁 时按需拉详情并短暂显示，不缓存到全局变量 */
async function revealSecret(btn) {
  const span = $(btn.dataset.sec);
  try {
    const detail = await api('/api/assets/' + btn.dataset.aid);
    const f = (detail.fields || [])[Number(btn.dataset.fidx)];
    if (!f) { toast('字段不存在', true); return; }
    span.textContent = f.value;
    btn.textContent = '🙈';
    btn.dataset.revealed = '1';
  } catch (err) {
    toast('获取明文失败：' + err.message, true);
  }
}
function hideSecret(btn) {
  const span = $(btn.dataset.sec);
  span.textContent = maskSecret();
  btn.textContent = '👁';
  delete btn.dataset.revealed;
}
function toggleSecret(btn) {
  if (btn.dataset.revealed === '1') hideSecret(btn);
  else revealSecret(btn);
}

async function handleCopy(btn) {
  let txt = null;
  if (btn.dataset.txt !== undefined) {
    txt = btn.dataset.txt;
  } else if (btn.dataset.fidx !== undefined) {
    if (btn.dataset.revealed === '1') {
      txt = $(btn.dataset.sec).textContent;
    } else {
      try {
        const detail = await api('/api/assets/' + btn.dataset.aid);
        const f = (detail.fields || [])[Number(btn.dataset.fidx)];
        txt = f ? f.value : null;
      } catch (err) {
        toast('获取明文失败：' + err.message, true);
        return;
      }
    }
  }
  if (txt === null) { toast('复制失败', true); return; }
  try {
    await navigator.clipboard.writeText(txt);
    toast('已复制');
  } catch (err) {
    toast('复制失败（浏览器不支持剪贴板）', true);
  }
}

async function deleteAsset(id) {
  const a = state.assets.find((x) => x.id === id);
  if (!confirm(`确定删除「${a ? a.name : '该资产'}」？此操作不可恢复。`)) return;
  try {
    const data = await api('/api/assets/' + id, { method: 'DELETE' });
    applyChangeResult(data, '已删除');
    await refreshAll();
  } catch (err) {
    toast('删除失败：' + err.message, true);
  }
}

/* ================= 搜索 ================= */
async function doSearch() {
  if (!state.q) {
    state.results = state.assets;
    renderList();
    return;
  }
  try {
    state.results = await api('/api/search?q=' + encodeURIComponent(state.q));
  } catch (err) {
    state.results = [];
    toast('搜索失败：' + err.message, true);
  }
  renderList();
}

/* ================= 视图切换 ================= */
function switchView(v) {
  state.view = v;
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.view === v));
  $('sidebar').classList.toggle('hidden', v !== 'assets');
  $('view-assets').classList.toggle('hidden', v !== 'assets');
  $('view-approval').classList.toggle('hidden', v !== 'approval');
  $('view-backup').classList.toggle('hidden', v !== 'backup');
  $('view-upgrade').classList.toggle('hidden', v !== 'upgrade');
  $('view-settings').classList.toggle('hidden', v !== 'settings');
  if (v === 'approval') { if (!isLegacyReadonly()) { loadApprovals(); loadApprovalHistory(); } }
  if (v === 'backup') { loadBackupStatus(); loadBackupHistory(); }
  if (v === 'upgrade') renderUpgradeView();
  if (v === 'settings') {
    if (isLegacyReadonly()) { $('ai-token').textContent = '旧版库不适用'; } else loadToken();
    loadAiSettings();  // US4：开关权威在服务端，每次进设置页重新拉取，不信任本地缓存
  }
}

/* ================= AI 审批 ================= */
function reqType(opType) {
  return { create: '新建', update: '修改', delete: '删除' }[opType] || opType;
}
function reqIcon(opType) {
  return { create: '📥', update: '✏️', delete: '🗑️' }[opType] || '📋';
}
function reqTitle(payload, opType) {
  const name = payload.name || (payload.id !== undefined ? assetName(payload.id) : '资产');
  if (opType === 'create') return '新建「' + name + '」';
  if (opType === 'update') return '修改「' + name + '」';
  return '删除「' + name + '」';
}
// US5：优先级枚举的中文展示（审批预览用，落库值仍为 high/normal/low）
const PRIORITY_TEXT = { high: '高', normal: '普通', low: '低' };

function reqRows(payload, opType) {
  const name = payload.name || (payload.id !== undefined ? assetName(payload.id) : '资产');
  if (opType === 'delete') return [[name, '（整条删除）', '-', '否']];
  const rows = [];
  if (opType === 'update' && !(payload.fields && payload.fields.length)) {
    const labelMap = { name: '名称', category_key: '分类', provider: '服务商', status: '状态', risk: '风险', icon: '图标' };
    for (const k of ['name', 'category_key', 'provider', 'status', 'risk']) {
      if (k in payload) rows.push([name, labelMap[k] || k, String(payload[k]), '否']);
    }
    if (!rows.length) rows.push([name, '（修改资产信息）', '-', '否']);
  }
  // US5：两列均为普通非敏感属性，预览明文可见；清空到期日展示为「未设置」
  if ('priority' in payload) {
    rows.push([name, '优先级', PRIORITY_TEXT[payload.priority] || String(payload.priority), '否']);
  }
  if ('due_date' in payload) {
    rows.push([name, '到期日', payload.due_date ? String(payload.due_date) : '未设置', '否']);
  }
  (payload.fields || []).forEach((f) => {
    rows.push([name, f.label || '字段', f.sensitive ? maskSecret() : String(f.value), f.sensitive ? '🔒 敏感' : '否']);
  });
  return rows;
}
function renderReqs() {
  const n = state.reqs.length;
  $('approval-badge').textContent = n;
  $('approve-all-btn').textContent = `✓ 全部批准（${n} 项）`;
  $('approve-all-btn').disabled = n === 0;
  $('req-list').innerHTML = state.reqs.map((r) => {
    const rows = reqRows(r.payload, r.op_type).map((rw) =>
      `<tr>${rw.map((c) => `<td class="${c.includes('敏感') ? 'pv-secret' : ''}">${esc(c)}</td>`).join('')}</tr>`).join('');
    return `<div class="req-card" data-id="${r.id}">
      <div class="req-head"><div class="req-ico">${reqIcon(r.op_type)}</div>
        <div class="req-title"><div class="t">${esc(reqType(r.op_type))}：${esc(reqTitle(r.payload, r.op_type))}</div><div class="m">${esc(fmtTime(r.created_at))} · 点击卡片展开字段明细</div></div>
        <div class="req-actions">
          <button class="btn-reject" data-id="${r.id}">拒绝</button>
          <button class="btn-approve" data-id="${r.id}">批准</button>
        </div></div>
      <div class="req-preview">
        <table class="preview-table"><thead><tr><th>资产</th><th>字段</th><th>内容</th><th>敏感</th></tr></thead><tbody>${rows}</tbody></table>
      </div></div>`;
  }).join('') || (isLegacyReadonly()
    ? '<div class="empty">旧版库为只读模式：AI 审批在副本升级到新版后可用。<br>副本升级请前往「升级兼容」页。</div>'
    : '<div class="empty">没有待审批的请求</div>');
}
async function approveReq(id) {
  try {
    const data = await api(`/api/approvals/${id}/approve`, { method: 'POST' });
    applyChangeResult(data, '已批准');
    await refreshAll();
  } catch (err) {
    toast('批准失败：' + err.message, true);
  }
}
async function rejectReq(id) {
  try {
    const data = await api(`/api/approvals/${id}/reject`, { method: 'POST' });
    applyChangeResult(data, '已拒绝');  // 拒绝同样一次落盘一次备份，按双结果提示
    await refreshAll();
  } catch (err) {
    toast('拒绝失败：' + err.message, true);
  }
}
async function approveAll() {
  const ids = state.reqs.map((r) => r.id);
  if (!ids.length) return;
  if (!confirm(`将批准全部 ${ids.length} 项请求并写入保险库，确定？`)) return;
  $('approve-all-btn').disabled = true;
  try {
    let last = null;
    for (const id of ids) last = await api(`/api/approvals/${id}/approve`, { method: 'POST' });
    applyChangeResult(last, '已全部批准');
    await refreshAll();
  } catch (err) {
    toast('批量批准中断：' + err.message, true);
    await loadApprovals();
  } finally {
    $('approve-all-btn').disabled = state.reqs.length === 0;
  }
}

async function loadApprovalHistory() {
  try {
    state.approvalHistory = await api('/api/approvals/history?limit=30');
    renderApprovalHistory();
  } catch (err) {
    state.approvalHistory = [];
    renderApprovalHistory();
  }
}
function renderApprovalHistory() {
  const list = $('approval-history-list');
  if (!list) return;
  const items = state.approvalHistory;
  if (!items.length) {
    list.innerHTML = '<div class="history-empty">还没有已处理的记录</div>';
    return;
  }
  list.innerHTML = items.map((h) => {
    const approved = h.status === 'approved';
    const resultTxt = h.op_type === 'create'
      ? (approved ? `已写入为资产 #${h.result_asset_id || ''}` : '未写入')
      : (approved ? '已生效' : '已驳回，未改动');
    return `<div class="history-row">
      <span class="h-time">${esc(fmtTime(h.processed_at))}</span>
      <span class="h-badge ${approved ? 'h-approved' : 'h-rejected'}">${approved ? '✓ 已批准' : '✕ 已拒绝'}</span>
      <span class="h-op">${esc(reqType(h.op_type))}</span>
      <span class="h-result">${esc(resultTxt)}</span>
    </div>`;
  }).join('');
}

/* ================= 新增 / 编辑资产 ================= */
function fillCatSelect(selected) {
  const sel = $('f-cat');
  sel.innerHTML = '<option value="">未分类</option>' +
    state.cats.map((c) => `<option value="${esc(c.key)}">${esc(c.name)}</option>`).join('');
  sel.value = selected;
}
function renderFieldEditor() {
  $('field-editor').innerHTML = editFields.map((f, i) => `
    <div class="field-edit" data-i="${i}">
      <input class="fe-label" value="${esc(f.l)}" placeholder="字段名" autocomplete="off">
      <input class="fe-value" value="${esc(f.v)}" placeholder="值" autocomplete="off">
      <span class="fe-secret" data-i="${i}">${f.sens ? '🔒 敏感' : '🔓 普通'}</span>
      <button class="fe-del" data-i="${i}">✕</button>
    </div>`).join('');
}
// US5：分段控件的权威值存在 hidden input，按钮只负责切换高亮与写值
function setPriorityValue(v) {
  $('f-priority').value = v;
  document.querySelectorAll('#f-priority-seg .seg-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.priority === v);
  });
}

function openCreateModal() {
  $('modal-title').textContent = '➕ 新增资产';
  state.editAssetId = null;
  $('f-name').value = '';
  fillCatSelect(state.cats.length ? state.cats[0].key : '');
  $('f-status').value = 'normal';
  // US5：新增默认普通优先级、空到期日
  setPriorityValue('normal');
  $('f-due-date').value = '';
  editFields = [
    { l: '账号', v: '', sens: false, kind: 'text' },
    { l: '密码', v: '', sens: true, kind: 'secret' },
    { l: '备注', v: '', sens: false, kind: 'note' },
  ];
  renderFieldEditor();
  $('asset-modal').classList.remove('hidden');
  $('f-name').focus();
}
async function openEditModal(id) {
  try {
    const a = await api('/api/assets/' + id);
    $('modal-title').textContent = '✏️ 编辑资产';
    state.editAssetId = id;
    $('f-name').value = a.name || '';
    fillCatSelect(a.category_key || '');
    $('f-status').value = a.status || 'normal';
    // US5：回填优先级与到期日（无到期日为空，由保存载荷显式转 null）
    setPriorityValue(a.priority || 'normal');
    $('f-due-date').value = a.due_date || '';
    // 敏感字段以掩码占位展示，保存时若未改动再按需取原文（明文不驻留内存）
    editFields = (a.fields || []).map((f) => ({
      l: f.label,
      v: f.sensitive ? maskSecret() : f.value,
      sens: !!f.sensitive,
      kind: f.kind || (f.sensitive ? 'secret' : 'text'),
      fid: f.id,
    }));
    renderFieldEditor();
    $('asset-modal').classList.remove('hidden');
  } catch (err) {
    toast('加载资产失败：' + err.message, true);
  }
}
function closeModal() {
  $('asset-modal').classList.add('hidden');
  state.editAssetId = null;
  $('f-name').value = '';
  $('f-status').value = 'normal';
  // US5：关闭即重置两控件到默认态，不残留上一次输入
  setPriorityValue('normal');
  $('f-due-date').value = '';
  editFields = [];
  $('field-editor').innerHTML = '';
}
async function saveAsset() {
  const name = $('f-name').value.trim();
  if (!name) { toast('名称不能为空', true); return; }
  if (editFields.some((f) => !f.l.trim())) { toast('字段名不能为空', true); return; }
  $('modal-save').disabled = true;
  try {
    // 编辑时敏感字段若保持掩码未改，则按需拉取原文（仅本次请求内使用，不缓存）
    let realById = null;
    if (state.editAssetId !== null &&
        editFields.some((f) => f.v === maskSecret() && f.fid != null)) {
      const detail = await api('/api/assets/' + state.editAssetId);
      realById = {};
      (detail.fields || []).forEach((df) => { realById[df.id] = df.value; });
    }
    const fields = editFields.map((f, i) => {
      let value = f.v;
      if (f.v === maskSecret() && realById && f.fid != null && realById[f.fid] !== undefined) {
        value = realById[f.fid];
      }
      return { label: f.l.trim(), value, sensitive: !!f.sens, kind: f.kind || (f.sens ? 'secret' : 'text'), sort_order: i };
    });
    const payload = {
      name,
      category_key: $('f-cat').value,
      status: $('f-status').value,
      // US5：优先级取分段控件权威值；到期日清空时显式 null，后端落 SQL NULL
      priority: $('f-priority').value,
      due_date: $('f-due-date').value ? $('f-due-date').value : null,
      fields,
    };
    let data;
    if (state.editAssetId !== null) {
      data = await api('/api/assets/' + state.editAssetId, { method: 'PUT', body: payload });
    } else {
      data = await api('/api/assets', { method: 'POST', body: payload });
    }
    closeModal();
    applyChangeResult(data, '已保存');
    await refreshAll();
  } catch (err) {
    toast('保存失败：' + err.message, true);
  } finally {
    $('modal-save').disabled = false;
  }
}

/* ================= 分类管理 ================= */
function openCatManager() {
  originalCats = state.cats.map((c) => ({ key: c.key, name: c.name, icon: c.icon, sort_order: c.sort_order }));
  editCats = state.cats.map((c) => ({ key: c.key, name: c.name, icon: c.icon }));
  renderCatList();
  $('cat-modal').classList.remove('hidden');
}
function closeCatManager() {
  $('cat-modal').classList.add('hidden');
  editCats = [];
  originalCats = [];
}
function renderCatList() {
  $('cat-list').innerHTML = editCats.map((c, i) => `
    <div class="cat-edit-row" data-i="${i}">
      <span class="cat-ico">${esc(c.icon)}</span>
      <input class="cat-name" value="${esc(c.name)}" autocomplete="off">
      <span class="cat-move">
        <button data-act="up" data-i="${i}" ${i === 0 ? 'disabled style="opacity:.3"' : ''}>↑</button>
        <button data-act="down" data-i="${i}" ${i === editCats.length - 1 ? 'disabled style="opacity:.3"' : ''}>↓</button>
      </span>
      <button class="cat-del" data-i="${i}">✕</button>
    </div>`).join('');
}
function moveCat(i, dir) {
  const j = i + dir;
  if (j < 0 || j >= editCats.length) return;
  [editCats[i], editCats[j]] = [editCats[j], editCats[i]];
  renderCatList();
}
function delCatRow(i) {
  const c = editCats[i];
  const n = state.assets.filter((a) => a.category_key === c.key).length;
  if (n > 0 && !confirm(`「${c.name}」下有 ${n} 条资产，删除后这些资产会变成「未分类」。确定删除？`)) return;
  editCats.splice(i, 1);
  renderCatList();
}
async function saveCatManager() {
  $('cat-save').disabled = true;
  const finalKeys = new Set(editCats.map((c) => c.key));
  const ops = [];
  editCats.forEach((c, i) => {
    const sortOrder = i + 1;
    const name = c.name.trim() || '未命名';
    const orig = originalCats.find((o) => o.key === c.key);
    if (!orig) {
      ops.push(['create', { key: c.key, name, icon: c.icon || '🏷️', sort_order: sortOrder }]);
    } else if (orig.name !== name || orig.icon !== c.icon || orig.sort_order !== sortOrder) {
      ops.push(['update', c.key, { name, icon: c.icon || '🏷️', sort_order: sortOrder }]);
    }
  });
  originalCats.forEach((o) => { if (!finalKeys.has(o.key)) ops.push(['delete', o.key]); });
  try {
    let last = null;
    for (const op of ops) {
      if (op[0] === 'create') last = await api('/api/categories', { method: 'POST', body: op[1] });
      else if (op[0] === 'update') last = await api('/api/categories/' + encodeURIComponent(op[1]), { method: 'PUT', body: op[2] });
      else last = await api('/api/categories/' + encodeURIComponent(op[1]), { method: 'DELETE' });
    }
    if (!finalKeys.has(state.cat)) state.cat = 'all';
    closeCatManager();
    applyChangeResult(last || {}, '分类已保存');
    await refreshAll();
  } catch (err) {
    toast('保存分类失败：' + err.message, true);
  } finally {
    $('cat-save').disabled = false;
  }
}

/* ================= 保存/备份双结果（对照原型 02、03） ================= */
const BACKUP_ERROR_TEXT = {
  backup_failed: '备份位置空间不足或写入失败',
  backup_permissions_failed: '备份位置访问权限不足',
  package_too_large: '备份超过大小上限',
};

function backupFailText(code) {
  return BACKUP_ERROR_TEXT[code] || '备份未完成';
}

function renderSaveBackupBanner() {
  const el = $('save-backup-banner');
  const b = state.lastBackupFailure;
  if (!b) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  el.className = 'warn-banner2';
  el.innerHTML = `<div style="font-size:18px">⚠️</div>
    <div class="banner-txt"><b>数据已保存，自动备份失败</b>
      <div class="banner-sub">${esc(backupFailText(b.error_code))}。上一份有效备份仍保留；请处理后重试，重试只备份最新状态。</div>
    </div>
    <button class="btn-ghost btn-retry-backup" id="retry-backup-banner-btn">只重试备份</button>`;
  el.classList.remove('hidden');
}

/* 持久化改变成功后统一处理 persistence/backup 双结果；不得引导重做已保存的业务 */
function applyChangeResult(data, okText) {
  const backup = data && data.backup;
  if (backup && backup.status === 'failed') {
    state.lastBackupFailure = backup;
    renderSaveBackupBanner();
    toast(okText + '；但备份失败', true);
  } else {
    state.lastBackupFailure = null;
    renderSaveBackupBanner();
    toast(okText);
  }
}

async function retryBackup() {
  const btn = document.getElementById('retry-backup-banner-btn');
  if (btn) btn.disabled = true;
  try {
    const result = await api('/api/backup/retry', { method: 'POST' });
    const b = result.backup || result;
    if (b.status === 'ok') {
      state.lastBackupFailure = null;
      renderSaveBackupBanner();
      toast('备份已完成并回读验证');
    } else {
      state.lastBackupFailure = b;
      renderSaveBackupBanner();
      toast('重试仍失败：' + backupFailText(b.error_code), true);
    }
    if (state.view === 'backup') {
      await loadBackupStatus();
      await loadBackupHistory();  // 重试成功会新增一份备份，历史清单同步刷新
    }
  } catch (err) {
    toast('重试失败：' + err.message, true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ================= 备份与恢复视图（对照原型 02、15） ================= */
async function loadBackupStatus() {
  if (!state.token) return;
  try {
    state.backupStatus = await api('/api/backup/status');
  } catch (err) {
    state.backupStatus = null;
    toast('加载备份状态失败：' + err.message, true);
  }
  renderBackupView();
}

function renderBackupView() {
  const bar = $('backup-status-bar'), grid = $('backup-latest-grid');
  const actions = $('backup-actions'), latest = $('backup-latest-line');
  const sameDisk = $('backup-same-disk-note');
  const st = state.backupStatus;
  if (!st || st.state !== 'ready') {
    const legacy = isLegacyReadonly();
    bar.className = 'backup-status-bar';
    bar.innerHTML = `<span class="dot" style="background:var(--gray)"></span><span>${legacy
      ? '旧版库为只读：新版自动备份状态在副本升级后启用' : '备份状态将在解锁后显示'}</span>`;
    latest.textContent = legacy
      ? '旧材料转换与副本升级请前往「升级兼容」页。'
      : '解锁后查看最近一次已验证备份。';
    grid.innerHTML = '';
    actions.innerHTML = '';
    sameDisk.classList.add('hidden');
    return;
  }
  const ok = st.status === 'ok';
  const failed = st.status === 'failed';
  bar.className = 'backup-status-bar ' + (ok ? 'ok' : (failed ? 'bad' : 'warn'));
  bar.innerHTML = `<span class="dot"></span>
    <span>${ok ? '最近保存已完成备份验证' : (failed ? '数据已保存，备份失败' : '最近一次保存的备份尚未验证')}</span>
    <span class="bar-time">${st.last_success_at ? esc(fmtTime(st.last_success_at)) : ''}</span>
    <span class="bar-right">本机自动备份 · local_only</span>`;
  latest.innerHTML = ok
    ? '<span class="verify-badge">已验证</span> 已保存并回读验证'
    : `<span class="${failed ? 'bad-badge' : 'warn-badge'}">${failed ? '备份失败' : '待验证'}</span> ${esc(backupFailText(st.error_code))}`;
  grid.innerHTML = `
    <div class="cell"><div class="k">已验证序号</div><div class="v">${esc(String(st.latest_verified_seq ?? 0))}</div><div class="d">当前库序号 ${esc(String(st.latest_saved_seq ?? 0))}</div></div>
    <div class="cell"><div class="k">备份位置</div><div class="v">本机加密包</div><div class="d">.avbak · 每包独立随机密钥</div></div>
    <div class="cell"><div class="k">最近成功</div><div class="v">${st.last_success_at ? esc(fmtTime(st.last_success_at)) : '—'}</div><div class="d">时间来自非敏感清单</div></div>`;
  sameDisk.classList.toggle('hidden', st.local_only === false);
  let html = '';
  if (st.retry_available) {
    html += '<button class="btn-primary" style="width:auto" id="backup-retry-btn">只重试备份</button>';
  }
  html += '<button class="btn-ghost" id="backup-export-inline">导出加密备份</button>';
  actions.innerHTML = html;
}

const BACKUP_PURPOSE_TEXT = {
  auto: '自动备份', manual: '手动导出', pre_restore: '恢复前保护',
  pre_migrate: '升级前保护', rollback_preserve: '回退保全',
};
async function loadBackupHistory() {
  if (!state.token) return;
  const list = $('backup-history-list');
  if (list) list.innerHTML = '<div class="history-empty">加载中…</div>';
  try {
    const data = await api('/api/backup/history?limit=30');
    state.backupHistory = data.items || [];
  } catch (err) {
    state.backupHistory = [];
  }
  renderBackupHistory();
}
function fmtSize(n) {
  if (!Number.isFinite(n)) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}
function renderBackupHistory() {
  const list = $('backup-history-list');
  if (!list) return;
  const items = state.backupHistory;
  if (!items.length) {
    list.innerHTML = '<div class="history-empty">还没有备份；第一次保存资产后会自动生成。</div>';
    return;
  }
  const shown = items.slice(0, state.backupHistoryShown);
  const rows = shown.map((b) => {
    const purposeTxt = BACKUP_PURPOSE_TEXT[b.purpose] || b.purpose;
    const epochTag = b.current_epoch === false
      ? '<span class="old-epoch-tag" title="改主密码或恢复之前的备份，需用当时的主密码打开">旧代次</span>' : '';
    return `<div class="history-row">
      <span class="h-seq">#${esc(String(b.change_seq))}</span>
      <span class="h-time">${esc(fmtTime(b.captured_at))}</span>
      <span class="h-purpose">${esc(purposeTxt)}</span>
      ${epochTag}
      <span class="h-size">${esc(fmtSize(b.size))}</span>
      <button class="btn-ghost h-download" data-id="${esc(b.backup_id)}" type="button">下载这份备份</button>
    </div>`;
  }).join('');
  const more = items.length > shown.length
    ? `<button class="history-more" id="backup-history-more" type="button">展开全部 ${items.length} 条 ▾</button>`
    : '';
  list.innerHTML = rows + more;
}
async function downloadHistoryBackup(backupId) {
  try {
    const res = await desktopFetch('/api/backup/history/' + encodeURIComponent(backupId) + '/export', {
      headers: state.token ? { Authorization: 'Bearer ' + state.token } : {},
    });
    if (!res.ok) throw new Error('下载失败（' + res.status + '）');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vault-backup-#' + backupId + '.avbak';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast('历史备份已下载；打开它需要该备份当时的主密码');
  } catch (err) {
    toast(err.message, true);
  }
}

/* ================= 设置 ================= */
async function copyAiToken() {
  const t = $('ai-token').textContent;
  if (!t || t === '—') { toast('令牌为空', true); return; }
  try {
    await navigator.clipboard.writeText(t);
    toast('已复制');
  } catch (err) {
    toast('复制失败（浏览器不支持剪贴板）', true);
  }
}
async function resetAiToken() {
  // 对照原型 09：主动更换令牌不删除待审批内容；仅旧令牌立即失效
  if (!confirm('重新生成后旧令牌立即失效（使用旧令牌的 AI 请求会被拒绝），待审批内容保留。确定？')) return;
  try {
    const data = await api('/api/token/reset', { method: 'POST' });
    $('ai-token').textContent = data.ai_token || '';
    applyChangeResult(data, '令牌已重新生成，旧令牌已失效');
  } catch (err) {
    toast('重新生成失败：' + err.message, true);
  }
}
async function exportBackup() {
  try {
    const res = await desktopFetch('/api/backup/export', {
      headers: state.token ? { Authorization: 'Bearer ' + state.token } : {},
    });
    if (!res.ok) {
      let data = null;
      try { data = await res.json(); } catch (err) { /* 忽略 */ }
      const ce = new Error((data && data.error) || '导出失败（' + res.status + '）');
      ce.code = data && data.code;
      throw ce;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const now = new Date();
    const p = (n) => String(n).padStart(2, '0');
    const ts = `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
    a.href = url;
    a.download = 'vault-backup-' + ts + '.avbak'; // AVBK0002 加密包；恢复时仍需导出时的主密码
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast('备份已导出；请妥善保管，建议另存到独立设备');
    // 导出会在受管目录留一份副本，即时让「备份记录」出现新行
    if (state.view === 'backup') await loadBackupHistory();
  } catch (err) {
    toast(errCode(err) === 'vault_not_ready'
      ? '当前库状态不支持导出（旧版只读库请先在「升级兼容」页升级副本）' : err.message, true);
  }
}

/* ================= 升级兼容（对照原型截图 10–11；T045） ================= */
function renderUpgradeView() {
  const legacy = isLegacyReadonly();
  $('upgrade-readonly-badge').classList.toggle('hidden', !legacy);
  $('upgrade-source-badge').textContent = legacy ? '检测到旧格式 · 只读' : '旧库副本升级';
}

function sourceStateText(s) {
  return {
    legacy_read_only: '旧格式副本（可升级）',
    ready_locked: '已是新版格式（无需升级）',
    maintenance_failed: '处于维护冻结（不可升级）',
    unsupported: '不支持的格式',
    corrupt: '文件已损坏',
    uninitialized: '未初始化（不可升级）',
    missing: '文件不存在',
  }[s] || (s || '未知状态');
}

function setUpgradeButtons() {
  const prepare = $('upgrade-prepare-btn'), commit = $('upgrade-commit-btn');
  const retry = $('upgrade-retry-btn'), cancel = $('upgrade-cancel');
  prepare.classList.toggle('hidden', upgradeStep !== 1);
  commit.classList.toggle('hidden', upgradeStep !== 2);
  retry.classList.toggle('hidden', upgradeStep !== 3 || !retry.dataset.show);
  if (upgradeStep === 2) commit.disabled = !$('upgrade-confirm-box').checked;
  cancel.textContent = upgradeStep === 1 ? '取消' : (upgradeStep === 2 ? '上一步' : '完成');
}

function resetUpgradePanels() {
  $('upgrade-step1').classList.remove('hidden');
  $('upgrade-step2').classList.add('hidden');
  $('upgrade-result').classList.add('hidden');
  $('upgrade-err1').textContent = '';
  $('upgrade-err2').textContent = '';
  $('upgrade-confirm-box').checked = false;
  $('upgrade-source-password').value = '';
  $('upgrade-retry-btn').dataset.show = '';
  upgradeOp = null;
  upgradeSource = null;
  upgradeStep = 1;
  clearInterval(upgradeCountdown);
  upgradeCountdown = null;
}

async function openUpgradeWizard() {
  resetUpgradePanels();
  setUpgradeButtons();
  $('upgrade-modal').classList.remove('hidden');
  const sel = $('upgrade-source-select'), hint = $('upgrade-source-hint');
  sel.innerHTML = '<option>正在读取已配置副本…</option>';
  $('upgrade-prepare-btn').disabled = true;
  try {
    migrationSources = await api('/api/migration/sources');
  } catch (err) {
    migrationSources = null;
    sel.innerHTML = '<option>读取副本列表失败</option>';
    $('upgrade-err1').textContent = '读取副本列表失败：' + err.message;
    return;
  }
  if (!migrationSources.length) {
    // 白名单默认空：功能默认关闭，界面不接受手填路径
    sel.innerHTML = '<option value="">未配置可升级副本</option>';
    sel.disabled = true;
    hint.textContent = '副本升级默认关闭：需由本程序的安全配置指定独立副本路径，界面不能输入任意路径。';
    return;
  }
  sel.disabled = false;
  hint.textContent = '只列出安全配置中的独立副本；日常活动库不会出现在可升级项中。';
  sel.innerHTML = migrationSources.map((s) => {
    const selectable = s.state === 'legacy_read_only';
    return `<option value="${esc(s.id)}" ${selectable ? '' : 'disabled'}>${esc(s.id)} — ${esc(sourceStateText(s.state))}</option>`;
  }).join('');
  const firstSelectable = migrationSources.find((s) => s.state === 'legacy_read_only');
  if (firstSelectable) {
    sel.value = firstSelectable.id;
    upgradeSource = firstSelectable.id;
    $('upgrade-prepare-btn').disabled = false;
  } else {
    upgradeSource = null;
    $('upgrade-prepare-btn').disabled = true;
  }
}

function closeUpgradeWizard() {
  $('upgrade-modal').classList.add('hidden');
  resetUpgradePanels();
}

function migrationPrepareError(err) {
  switch (errCode(err)) {
    case 'invalid_identity_or_credentials':
    case 'invalid_credentials_or_corrupt':
      return '副本主密码不正确，或副本文件已损坏';
    case 'migration_not_required':
      return '这份副本已是新版格式，无需升级';
    case 'unsupported_legacy_format':
      return '副本格式不受支持（较新版本、未知结构、未初始化或已损坏）：已停止，未改动副本';
    case 'pre_backup_failed':
      return '升级前的加密备份未能完成（如磁盘空间不足）：副本未改动，处理后可重试';
    case 'migration_source_is_active':
      return '该路径是日常活动库，不能作为副本升级；请复制出独立副本后由安全配置指定';
    case 'migration_source_not_configured':
      return '该副本未在安全配置中，拒绝访问';
    case 'backup_key_required':
      return '请先输入该副本的主密码';
    default:
      return '核验失败：' + err.message;
  }
}

async function prepareUpgrade() {
  const source = $('upgrade-source-select').value;
  const password = $('upgrade-source-password').value;
  const known = (migrationSources || []).find((s) => s.id === source);
  if (!known || known.state !== 'legacy_read_only') {
    $('upgrade-err1').textContent = '请选择可升级的旧格式副本'; return;
  }
  if (!password) { $('upgrade-err1').textContent = '请输入该副本的主密码'; return; }
  $('upgrade-err1').textContent = '';
  $('upgrade-prepare-btn').disabled = true;
  try {
    // 副本主密码错误返回 401 仅代表副本凭证无效，绝不能清掉主会话（skipSessionGuard）
    upgradeOp = await api('/api/migration/prepare', { method: 'POST', body: { source, password }, skipSessionGuard: true });
    upgradeSource = source;
    renderUpgradeStep2();
    upgradeStep = 2;
    setUpgradeButtons();
    startUpgradeCountdown();
  } catch (err) {
    $('upgrade-err1').textContent = migrationPrepareError(err);
  } finally {
    $('upgrade-prepare-btn').disabled = false;
  }
}

function renderUpgradeStep2() {
  const op = upgradeOp, c = op.counts || {}, pre = op.pre_backup || {};
  $('upgrade-step1').classList.add('hidden');
  $('upgrade-step2').classList.remove('hidden');
  $('upgrade-meta').innerHTML = `
    <div class="row"><span class="k">正式资产</span><span class="v">${esc(String(c.assets ?? 0))} 项 · 字段 ${esc(String(c.fields ?? 0))} 个 · 分类 ${esc(String(c.categories ?? 0))} 个</span></div>
    <div class="row"><span class="k">待审批内容</span><span class="v">${esc(String(c.pending ?? 0))} 条（同 id 重新加密保护，内容不变）</span></div>
    <div class="row"><span class="k">已处理审批</span><span class="v">${esc(String(c.processed ?? 0))} 条（仅保留非敏感审计记录）</span></div>
    <div class="row"><span class="k">升级前加密备份</span><span class="v">${pre.status === 'ok'
      ? `✅ 已回读验证 · 捕获于 ${esc(fmtTime(pre.captured_at))}` : '⚠️ 未完成'}</span></div>
    <div class="row"><span class="k">记录检查</span><span class="v">资产、字段、分类、关联与待审批逐项匹配</span></div>
    <div class="row"><span class="k">确认有效期</span><span class="v" id="upgrade-expires">${esc(String(op.expires_in))} 秒</span></div>`;
  $('upgrade-warning').textContent = op.warning || '';
}

function startUpgradeCountdown() {
  clearInterval(upgradeCountdown);
  let left = upgradeOp.expires_in;
  upgradeCountdown = setInterval(() => {
    left -= 1;
    const el = $('upgrade-expires');
    if (!el || $('upgrade-step2').classList.contains('hidden')) return clearInterval(upgradeCountdown);
    if (left <= 0) { clearInterval(upgradeCountdown); toast('升级确认已过期，请重新核验副本', true); return; }
    el.textContent = left + ' 秒';
  }, 1000);
}

function upgradeBackOrCancel() {
  if (upgradeStep === 1) { closeUpgradeWizard(); return; }
  if (upgradeStep === 3) { closeUpgradeWizard(); return; }
  // 从确认页回到选择页：旧确认 5 分钟后自动失效，重新核验即可
  clearInterval(upgradeCountdown); upgradeCountdown = null;
  upgradeOp = null;
  upgradeStep = 1;
  $('upgrade-step2').classList.add('hidden');
  $('upgrade-result').classList.add('hidden');
  $('upgrade-step1').classList.remove('hidden');
  setUpgradeButtons();
}

async function commitUpgrade() {
  if (!$('upgrade-confirm-box').checked) { $('upgrade-err2').textContent = '请先勾选确认：仅升级这份副本'; return; }
  $('upgrade-err2').textContent = '';
  $('upgrade-commit-btn').disabled = true;
  try {
    const result = await api('/api/migration/commit', {
      method: 'POST',
      // 副本确认失效也是 401，与主会话无关，不得清场
      skipSessionGuard: true,
      body: { source: upgradeSource, operation_id: upgradeOp.operation_id,
              confirmation_nonce: upgradeOp.confirmation_nonce, confirm_upgrade: true },
    });
    showUpgradeResult(result);
  } catch (err) {
    handleUpgradeFailure(err);
  } finally {
    $('upgrade-commit-btn').disabled = false;
  }
}

function showUpgradeResult(result) {
  clearInterval(upgradeCountdown); upgradeCountdown = null;
  upgradeStep = 3;
  $('upgrade-step1').classList.add('hidden');
  $('upgrade-step2').classList.add('hidden');
  $('upgrade-result').classList.remove('hidden');
  const body = $('upgrade-result-body');
  const retry = $('upgrade-retry-btn');
  if (result.result === 'committed') {
    retry.dataset.show = '';
    body.innerHTML = `<div class="restore-result-ok"><div class="big">✅</div>
      <div class="t">副本升级核验完成</div>
      <div class="d">副本已升级为新版格式，提交后磁盘回读核验通过，旧 DEK、正式资产、待审批与旧令牌效力均保留。</div></div>
      <div class="warn-note">日常使用入口尚未切换：日常库没有被修改或合并。正式迁移、本机解锁与跨设备恢复需要分别验收。</div>`;
  } else {
    retry.dataset.show = '1';
    body.innerHTML = `<div class="restore-result-ok"><div class="big">⚠️</div>
      <div class="t">副本已升级，升级后的备份失败</div>
      <div class="d">数据升级已完成并通过回读核验，只差一份后置备份；上一份有效备份仍保留。可只补备份，不会重做升级。</div></div>`;
  }
  setUpgradeButtons();
}

function handleUpgradeFailure(err) {
  const code = errCode(err);
  let icon = '❌', title = '升级未完成', detail;
  if (code === 'committed_data_invalid') {
    icon = '🛑'; title = '升级后数据核验异常';
    detail = '已进入保护状态并停止普通写入；操作前备份与已提交数据都已保留。请勿覆盖该副本目录，等待人工处理。';
  } else if (code === 'migration_target_changed' || code === 'confirmation_stale'
             || code === 'confirmation_expired' || code === 'invalid_confirmation') {
    icon = '⌛'; title = '确认已失效';
    detail = '核验后副本发生了变化，或确认已过期（5 分钟）。副本保持原样，请重新核验后再确认。';
  } else if (code === 'migration_failed' || code === 'migration_mismatch') {
    icon = '↩️'; title = '升级已停止，副本保持旧版';
    detail = '升级事务已整体回滚，副本仍是旧格式，记录未被改动。可重新核验后再试。';
  } else if (code === 'pre_backup_failed') {
    icon = '🛡️'; title = '升级前备份未完成';
    detail = '无法创建并验证升级前备份（如磁盘空间不足）。升级已停止，副本保持原样，处理后可重试。';
  } else if (code === 'unsupported_legacy_format') {
    icon = '🚧'; title = '不支持的副本格式';
    detail = '较新版本、未知结构、未初始化或损坏的副本一律拒绝：未做任何改动，也不会自动初始化。';
  } else {
    detail = esc(err.message) + '<br>副本保持原样，可重试。';
  }
  clearInterval(upgradeCountdown); upgradeCountdown = null;
  upgradeStep = 3;
  $('upgrade-step1').classList.add('hidden');
  $('upgrade-step2').classList.add('hidden');
  $('upgrade-result').classList.remove('hidden');
  $('upgrade-retry-btn').dataset.show = '';
  $('upgrade-result-body').innerHTML = `<div class="restore-result-ok"><div class="big">${icon}</div>
    <div class="t">${esc(title)}</div><div class="d">${detail}</div></div>`;
  setUpgradeButtons();
}

async function retryUpgradeBackup() {
  const btn = $('upgrade-retry-btn');
  btn.disabled = true;
  try {
    const result = await api('/api/migration/backup/retry', {
      method: 'POST',
      body: { source: upgradeSource, operation_id: upgradeOp.operation_id },
    });
    showUpgradeResult(result);
    toast(result.result === 'committed' ? '升级后的备份已补齐并验证' : '补备份仍失败，可再试');
  } catch (err) {
    toast('补备份失败：' + err.message, true);
  } finally {
    btn.disabled = false;
  }
}

/* ---------- 旧 .bin / schema1 包转换 ---------- */
function openLegacyInfo() { $('legacy-info-modal').classList.remove('hidden'); }
function closeLegacyInfo() { $('legacy-info-modal').classList.add('hidden'); }

function onLegacyFileChosen(file) {
  legacyFile = file;
  if (!file) return;
  const isAvbak = /\.avbak$/i.test(file.name);
  $('legacy-file-name').textContent = `已选择：${file.name}（${Math.ceil(file.size / 1024)} KB）`;
  $('legacy-pw-row').classList.toggle('hidden', !isAvbak);
  if (!isAvbak) {
    $('legacy-file-name').textContent += '；将使用当前会话中匹配的旧库密钥材料（DEK）';
    $('legacy-backup-password').value = '';
  }
  $('legacy-convert-btn').classList.remove('hidden');
}

function legacyConvertText(err) {
  switch (errCode(err)) {
    case 'legacy_key_required':
      return '缺少匹配的原库密钥材料：旧 .bin 必须在对应旧库的解锁会话中转换；仅凭文件和主密码无法转换，未生成任何文件';
    case 'invalid_credentials_or_corrupt':
      return '备份密码不正确，或材料已损坏';
    case 'migration_not_required':
      return '该材料已是新版格式，无需转换';
    case 'unsupported_legacy_format':
      return '材料格式不受支持：已停止，未生成文件';
    case 'invalid_package':
      return '不是有效的备份包，请确认文件完整';
    case 'legacy_convert_failed':
      return '转换失败：未生成任何文件，原材料保持不变';
    default:
      return '转换失败：' + err.message;
  }
}

async function convertLegacyMaterial() {
  if (!legacyFile) { toast('请先选择旧材料文件', true); return; }
  const isAvbak = /\.avbak$/i.test(legacyFile.name);
  const password = $('legacy-backup-password').value;
  if (isAvbak && !password) { toast('schema1 备份包（.avbak）需要输入该包的备份密码', true); return; }
  const btn = $('legacy-convert-btn');
  btn.disabled = true;
  try {
    const fd = new FormData();
    fd.append('file', legacyFile);
    if (isAvbak) fd.append('backup_password', password);
    const res = await desktopFetch('/api/backup/legacy/convert', {
      method: 'POST',
      headers: state.token ? { Authorization: 'Bearer ' + state.token } : {},
      body: fd,
    });
    if (!res.ok) {
      let data = null;
      try { data = await res.json(); } catch (err) { /* 忽略 */ }
      const ce = new Error((data && data.error) || '转换失败（' + res.status + '）');
      ce.code = data && data.code;
      throw ce;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const cd = res.headers.get('Content-Disposition') || '';
    const named = /filename\*?=(?:UTF-8'')?["']?([^;"']+)/i.exec(cd);
    a.href = url;
    a.download = named ? decodeURIComponent(named[1]) : ('vault-migrated-' + Date.now() + '.avbak');
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast('已转换为新版加密包并开始下载；请妥善保管，建议另存到独立设备');
    legacyFile = null;
    $('legacy-file-name').textContent = '';
    $('legacy-backup-password').value = '';
    $('legacy-pw-row').classList.add('hidden');
    $('legacy-convert-btn').classList.add('hidden');
    $('legacy-file').value = '';
  } catch (err) {
    toast(legacyConvertText(err), true);
  } finally {
    btn.disabled = false;
  }
}

/* ---------- 回退检查：只保全最新状态 ---------- */
function openRollback() {
  $('rollback-intro').classList.remove('hidden');
  $('rollback-result').classList.add('hidden');
  $('rollback-result').innerHTML = '';
  $('rollback-err').textContent = '';
  $('rollback-run-btn').classList.remove('hidden');
  $('rollback-run-btn').disabled = false;
  $('rollback-cancel').textContent = '返回';
  $('rollback-modal').classList.remove('hidden');
}
function closeRollback() { $('rollback-modal').classList.add('hidden'); }

async function runRollbackPreserve() {
  $('rollback-err').textContent = '';
  $('rollback-run-btn').disabled = true;
  try {
    const r = await api('/api/migration/rollback/prepare', { method: 'POST' });
    const b = r.backup || {};
    $('rollback-intro').classList.add('hidden');
    $('rollback-result').classList.remove('hidden');
    $('rollback-result').innerHTML = `
      <div class="restore-result-ok" style="padding:6px 6px 10px;"><div class="big">✅</div>
        <div class="t">最新状态已保全</div>
        <div class="d">当前库序号 #${esc(String(r.change_seq))} 已核验并封成保全包（编号 ${esc(String(b.backup_id || '').slice(0, 8))}）。</div></div>
      <div class="info-note">${esc(r.guidance || '')}</div>`;
    $('rollback-run-btn').classList.add('hidden');
    $('rollback-cancel').textContent = '完成';
  } catch (err) {
    if (errCode(err) === 'vault_not_ready') {
      $('rollback-err').textContent = '当前库不是可保全的新版库（旧版只读库无需回退保全）';
    } else if (errCode(err) === 'rollback_preserve_failed') {
      $('rollback-err').textContent = '保全包未能完成（如磁盘空间不足）：未改动当前库，处理后可重试';
    } else {
      $('rollback-err').textContent = '保全失败：' + err.message;
    }
  } finally {
    $('rollback-run-btn').disabled = false;
  }
}

/* ================= 删除全部数据（T031，FR-004，对照静态稿 05） =================
   独立危险操作，不挂卸载流程。双确认：勾选风险告知 + 输入 DELETE，缺一不可；
   弹窗不绑遮罩点击与 Esc，只有「取消」可退出。后端对绕过确认的请求一律 409。 */
function wipeReady() {
  return $('wipe-ack').checked === true &&
    String($('wipe-text').value || '').trim() === 'DELETE';
}
function updateWipeConfirm() {
  $('wipe-confirm').disabled = !wipeReady();
}
function openWipeConfirm() {
  $('wipe-ack').checked = false;
  $('wipe-text').value = '';
  $('wipe-err').textContent = '';
  updateWipeConfirm();
  $('wipe-modal').classList.remove('hidden');
}
function closeWipeConfirm() {
  $('wipe-modal').classList.add('hidden');
  $('wipe-ack').checked = false;
  $('wipe-text').value = '';
  updateWipeConfirm();
}
async function submitWipe() {
  // 函数级再校验一道：即便禁用态被绕过，未满足双确认也绝不发请求
  if (!wipeReady()) return;
  const btn = $('wipe-confirm');
  btn.disabled = true;
  try {
    await api('/api/maintenance/wipe-data', {
      method: 'POST',
      body: { acknowledge_risk: true, confirm_text: 'DELETE' },
    });
    closeWipeConfirm();
    toast('全部数据已永久删除');
    // 后端已作废全部会话并清空数据目录：回到首启两入口（missing 态）
    await returnToUnlock('全部数据已永久删除，程序已回到首次启动状态。');
  } catch (err) {
    if (errCode(err) === 'wipe_confirmation_required') {
      $('wipe-err').textContent = '确认信息不完整，操作未执行。';
    } else {
      $('wipe-err').textContent = '删除未能完成：' + (err.message || '数据未被清空');
    }
    updateWipeConfirm();
  }
}

/* ================= 修改主密码（T048，US3，对照静态稿 02） =================
   四状态：A 正常填写 / B 字段级校验错误 / C 前置备份阻断 / D 成功回解锁页。
   弹窗不绑遮罩点击与 Esc，只有「取消/保存」可关。密码规则权威在后端
   （6 位数字 fullmatch），前端只做填齐门禁与函数级再校验；后端错误码经
   errCode 一一映射到对应字段下方，不复制后端阈值与限流逻辑。 */
const PWD_CHANGE_PATH = '/api/vault/password/change';
const PWD_CHANGE_FIELDS = ['pwd-current', 'pwd-new', 'pwd-confirm'];
const PWD_CHANGE_ERROR_TEXT = {
  invalid_current_password: ['pwd-current', 'pwd-current-err', '当前密码不正确，库内容零变化'],
  password_rule_violated: ['pwd-new', 'pwd-new-err', '新密码必须是 6 位数字'],
  password_confirmation_mismatch: ['pwd-confirm', 'pwd-confirm-err', '两次输入的新密码不一致'],
};
function pwdChangeReady() {
  // 填齐门禁：三个输入都恰好 6 位（maxlength 已在 HTML 层拦住更长输入）
  return PWD_CHANGE_FIELDS.every((id) => String($(id).value || '').length === 6);
}
function clearPwdChangeErrors() {
  [['pwd-current', 'pwd-current-err'], ['pwd-new', 'pwd-new-err'],
   ['pwd-confirm', 'pwd-confirm-err']].forEach(([inputId, errId]) => {
    $(inputId).classList.remove('invalid');
    $(errId).textContent = '';
  });
}
function updatePwdChangeSubmit() {
  $('pwd-change-submit').disabled = !pwdChangeReady();
}
/* 状态 A：可填写表单（打开/重试/取消后都回到这里） */
function resetPwdChangeForm() {
  PWD_CHANGE_FIELDS.forEach((id) => {
    $(id).value = '';
    $(id).disabled = false;
  });
  clearPwdChangeErrors();
  $('pwd-change-warn').classList.remove('hidden');
  $('pwd-change-block').classList.add('hidden');
  $('pwd-change-cancel').textContent = '取消';
  $('pwd-change-submit').textContent = '保存修改';
  updatePwdChangeSubmit();
}
function openPwdChange() {
  resetPwdChangeForm();
  $('pwd-change-modal').classList.remove('hidden');
}
function closePwdChange() {
  $('pwd-change-modal').classList.add('hidden');
  resetPwdChangeForm();
}
/* 状态 C：前置备份失败阻断——输入停用，脚按钮切换为关闭/重试 */
function showPwdChangeBlocked() {
  $('pwd-change-warn').classList.add('hidden');
  $('pwd-change-block').classList.remove('hidden');
  PWD_CHANGE_FIELDS.forEach((id) => { $(id).disabled = true; });
  $('pwd-change-cancel').textContent = '关闭';
  $('pwd-change-submit').textContent = '重试';
  $('pwd-change-submit').disabled = false;
}
/* 重试：回到状态 A。保留已填内容供用户调整，不产生任何请求 */
function retryPwdChange() {
  PWD_CHANGE_FIELDS.forEach((id) => { $(id).disabled = false; });
  clearPwdChangeErrors();
  $('pwd-change-block').classList.add('hidden');
  $('pwd-change-warn').classList.remove('hidden');
  $('pwd-change-cancel').textContent = '取消';
  $('pwd-change-submit').textContent = '保存修改';
  updatePwdChangeSubmit();
}
async function submitPwdChange() {
  // 阻断态下主按钮是「重试」：只恢复表单，不发改密请求
  if (!$('pwd-change-block').classList.contains('hidden')) {
    retryPwdChange();
    return;
  }
  // 函数级再校验：即便禁用态被绕过，未填齐也绝不发请求
  if (!pwdChangeReady()) return;
  const btn = $('pwd-change-submit');
  btn.disabled = true;
  clearPwdChangeErrors();
  try {
    await api(PWD_CHANGE_PATH, {
      method: 'POST',
      body: {
        current_password: $('pwd-current').value,
        new_password: $('pwd-new').value,
        confirm_password: $('pwd-confirm').value,
      },
    });
    closePwdChange();
    // 状态 D：后端已作废全部会话并自锁，回解锁页由 forceRelock 清场，不自动代填
    await forceRelock('主密码已修改，请使用新主密码重新解锁。历史备份仍以旧密码封装，恢复时按备份生成时的密码输入。');
  } catch (err) {
    if (errCode(err) === 'pre_backup_failed') {
      showPwdChangeBlocked();
      return;
    }
    const mapped = PWD_CHANGE_ERROR_TEXT[errCode(err)];
    if (mapped) {
      const [inputId, errId, text] = mapped;
      $(inputId).classList.add('invalid');
      $(errId).textContent = text;
    } else {
      // 网络错误等未知失败：通用 toast 兜底，字段区不臆造文案
      toast('修改未能完成：' + (err.message || '请稍后重试'), true);
    }
    updatePwdChangeSubmit();
  }
}

/* ================= 恢复向导（对照原型 04–07、12） ================= */
const RESTORE_ICONS = { number: '①', done: '✔' };

function renderRestoreSteps() {
  const labels = ['选择备份', '验证内容', '确认恢复'];
  $('restore-steps').innerHTML = labels.map((label, i) => {
    const n = i + 1;
    const cls = n === restoreStep ? 'active' : (n < restoreStep ? 'done' : '');
    return `<div class="step ${cls}"><span class="no">${n < restoreStep ? RESTORE_ICONS.done : n}</span>${label}</div>`;
  }).join('');
}

function setRestoreButtons() {
  const next = $('restore-next'), commit = $('restore-commit');
  next.classList.toggle('hidden', restoreStep !== 1 && restoreStep !== 2);
  next.textContent = restoreStep === 1 ? '验证备份 →' : '下一步：确认恢复 →';
  commit.classList.toggle('hidden', restoreStep !== 3);
  commit.textContent = restoreMode === 'replace' ? '确认替换并恢复' : '开始恢复';
  if (restoreStep === 3) commit.disabled = !(restoreMode === 'empty' || $('restore-confirm-box').checked);
  $('restore-cancel').textContent = restoreStep === 1 ? '取消' : '上一步';
}

function openRestoreWizard() {
  restoreFile = null; restoreOp = null; restoreStep = 1;
  clearInterval(restoreCountdown); restoreCountdown = null;
  const vs = state.vaultState;
  // 空环境（缺失/未初始化）用一次性恢复凭证；已有库需已解锁会话
  const emptyEnv = !vs || vs.state === 'missing' || vs.state === 'uninitialized';
  if (!emptyEnv && !state.token) { toast('已有库恢复需先解锁，再到「备份与恢复」页操作', true); return; }
  if (vs && (vs.state === 'legacy_read_only')) {
    toast('旧版库为只读：副本升级与旧材料转换请在「升级兼容」页操作', true);
    return;
  }
  restoreMode = emptyEnv ? 'empty' : 'replace';
  $('restore-file-name').textContent = '选择一个加密备份文件（.avbak）';
  $('restore-backup-password').value = '';
  $('restore-err1').textContent = '';
  $('restore-step1').classList.remove('hidden');
  $('restore-step2').classList.add('hidden');
  $('restore-step3').classList.add('hidden');
  $('restore-result').classList.add('hidden');
  $('restore-confirm-box').checked = false;
  renderRestoreSteps();
  setRestoreButtons();
  $('restore-modal').classList.remove('hidden');
}

function closeRestoreWizard() {
  $('restore-modal').classList.add('hidden');
  restoreFile = null; restoreOp = null; restoreStep = 1;
  clearInterval(restoreCountdown); restoreCountdown = null;
  $('restore-backup-password').value = ''; // 密码只在内存，关闭即清
  $('restore-result-body').innerHTML = '';
}

async function prepareRestore() {
  if (!restoreFile) { $('restore-err1').textContent = '请先选择备份文件'; return; }
  const password = $('restore-backup-password').value;
  if (!password) { $('restore-err1').textContent = '请输入备份导出时的主密码'; return; }
  $('restore-err1').textContent = '';
  $('restore-next').disabled = true;
  try {
    const headers = {};
    if (restoreMode === 'empty') {
      // 空环境：先经 POST 领一次性恢复凭证（浏览器 POST 必带 Origin；凭证不成为会话）
      const cred = await api('/api/vault/restore-credential', { method: 'POST' });
      headers['X-Restore-Credential'] = cred.restore_credential;
    }
    const fd = new FormData();
    fd.append('file', restoreFile);
    fd.append('backup_password', password);
    // 备份密码/包错误返回 401（或 400），只代表这份备份的凭证无效，不清主会话
    restoreOp = await api('/api/backup/restore/prepare', { method: 'POST', body: fd, headers, skipSessionGuard: true });
    renderRestoreStep2();
    // 修复：验证通过后需把内容区从第 1 步切到第 2 步（此前只更新了指示条与按钮，核验页一直隐藏）
    $('restore-step1').classList.add('hidden');
    $('restore-step2').classList.remove('hidden');
    restoreStep = 2;
    renderRestoreSteps(); setRestoreButtons();
    startRestoreCountdown();
  } catch (err) {
    const code = errCode(err);
    if (code === RATE_LIMIT_CODE) {
      // FR-018：限流精确文案，不带「验证失败：」通用前缀
      $('restore-err1').textContent = RATE_LIMIT_TEXT;
    } else if (code === 'invalid_credentials_or_corrupt') {
      $('restore-err1').textContent = '备份或密码不正确：请确认文件与导出时的主密码';
    } else if (code === 'migration_required') {
      $('restore-err1').textContent = '这是旧版（schema1）备份包，不能直接恢复：请到「升级兼容」页先转换为新版包，再用新包恢复';
    } else {
      $('restore-err1').textContent = '验证失败：' + err.message;
    }
  } finally {
    $('restore-next').disabled = false;
  }
}

function restoreContentsText(op) {
  const c = op.contents || {};
  const n = (v) => Number.isFinite(Number(v)) ? Number(v) : 0;
  return `${n(c.asset_count)} 项资产 · ${n(c.pending_count)} 项待审批 · ${n(c.category_count)} 个分类 · ${n(c.field_count)} 个字段`;
}
function renderRestoreStep2() {
  const op = restoreOp;
  const pre = op.pre_backup;
  $('restore-meta').innerHTML = `
    <div class="row"><span class="k">备份内容</span><span class="v">${esc(restoreContentsText(op))}</span></div>
    <div class="row"><span class="k">备份捕获时间（已认证）</span><span class="v">${esc(fmtTime(op.captured_at))}</span></div>
    <div class="row"><span class="k">备份序号</span><span class="v">#${esc(String(op.change_seq))}</span></div>
    <div class="row"><span class="k">恢复方式</span><span class="v">${op.mode === 'replace' ? '替换当前库' : '空环境恢复'}</span></div>
    <div class="row"><span class="k">记录检查</span><span class="v">资产、字段、分类和关联匹配</span></div>
    ${pre ? `<div class="row"><span class="k">当前库保护备份</span><span class="v">${pre.status === 'ok' ? '✅ 已验证' : '⚠️ 未完成'}</span></div>` : ''}
    <div class="row"><span class="k">操作有效期</span><span class="v" id="restore-expires">${esc(String(op.expires_in))} 秒</span></div>`;
  $('restore-replace-note').textContent = op.warning || '';
  $('restore-replace-note').classList.remove('hidden');
}

function startRestoreCountdown() {
  clearInterval(restoreCountdown);
  let left = restoreOp.expires_in;
  restoreCountdown = setInterval(() => {
    left -= 1;
    const el = $('restore-expires');
    if (!el || !$('restore-step2') || $('restore-step2').classList.contains('hidden')) return clearInterval(restoreCountdown);
    if (left <= 0) { clearInterval(restoreCountdown); toast('确认已过期，请重新验证备份', true); return; }
    el.textContent = left + ' 秒';
  }, 1000);
}

function showRestoreStep3() {
  restoreStep = 3;
  renderRestoreSteps(); setRestoreStepsVisibilityForConfirm();
  $('restore-target-note').textContent =
    `目标时间：${fmtTime(restoreOp.captured_at)}。这是替换操作；更急的数据保存在恢复前保护备份中。`.replace('更急', '更新');
  $('restore-check-prebackup').textContent = restoreOp.pre_backup
    ? (restoreOp.pre_backup.status === 'ok' ? '✅ 当前库保护备份已验证' : '⚠️ 当前库保护备份未完成')
    : '✅ 空环境恢复：无需覆盖现有库';
  $('restore-confirm-row').classList.toggle('hidden', restoreMode !== 'replace');
  $('restore-err3').textContent = '';
  setRestoreButtons();
}

function setRestoreStepsVisibilityForConfirm() {
  $('restore-step1').classList.add('hidden');
  $('restore-step2').classList.add('hidden');
  $('restore-step3').classList.remove('hidden');
  $('restore-result').classList.add('hidden');
}

function restorePrev() {
  if (restoreStep === 1 || restoreStep >= 4) { closeRestoreWizard(); return; }
  clearInterval(restoreCountdown); restoreCountdown = null;
  if (restoreStep === 3) {
    // 回到验证内容页（操作未过期时可继续）
    restoreStep = 2;
    $('restore-step3').classList.add('hidden');
    $('restore-step2').classList.remove('hidden');
    renderRestoreSteps(); setRestoreButtons();
    startRestoreCountdown();
    return;
  }
  restoreStep = 1;
  restoreOp = null;
  $('restore-step3').classList.add('hidden');
  $('restore-step2').classList.add('hidden');
  $('restore-step1').classList.remove('hidden');
  renderRestoreSteps(); setRestoreButtons();
}

async function commitRestore() {
  if (restoreMode === 'replace' && !$('restore-confirm-box').checked) {
    $('restore-err3').textContent = '请先勾选确认替换，不会合并数据'; return;
  }
  $('restore-err3').textContent = '';
  $('restore-commit').disabled = true;
  try {
    const result = await api('/api/backup/restore/commit', {
      method: 'POST',
      // 确认令牌失效也是 401，针对本次恢复操作，不清主会话
      skipSessionGuard: true,
      body: { operation_id: restoreOp.operation_id, confirmation_nonce: restoreOp.confirmation_nonce,
              confirm_replace: restoreMode === 'replace' },
    });
    showRestoreResult(result);
  } catch (err) {
    handleRestoreFailure(err);
  } finally {
    $('restore-commit').disabled = false;
  }
}

function showRestoreResult(result) {
  clearInterval(restoreCountdown); restoreCountdown = null;
  restoreStep = 4;
  renderRestoreSteps();
  ['restore-step1', 'restore-step2', 'restore-step3'].forEach((id) => $(id).classList.add('hidden'));
  const body = $('restore-result-body');
  $('restore-result').classList.remove('hidden');
  $('restore-next').classList.add('hidden');
  if (result.result === 'committed') {
    body.innerHTML = `<div class="restore-result-ok"><div class="big">✅</div>
      <div class="t">恢复完成</div>
      <div class="d">所有旧会话已失效。请用<b>备份当时的主密码</b>重新解锁。</div></div>`;
  } else {
    body.innerHTML = `<div class="restore-result-ok"><div class="big">⚠️</div>
      <div class="t">已恢复，但恢复后的备份失败</div>
      <div class="d">数据已恢复完成。请重新解锁后到「备份与恢复」页只重试备份。</div></div>`;
  }
  $('restore-cancel').textContent = '完成';
  // 恢复提交成功即换代：本地会话作废，处理成功后重新解锁
  setTimeout(() => {
    closeRestoreWizard();
    forceRelock(result.result === 'committed'
      ? '恢复完成。请用备份当时的主密码解锁'
      : '已恢复，但恢复后的备份失败。请解锁后重试备份');
  }, 2600);
}

function handleRestoreFailure(err) {
  const msg = err.message || String(err);
  const code = errCode(err);
  if (code === RATE_LIMIT_CODE) {
    // FR-018：限流在结果面板精确呈现，说明解除方式，不包装成「恢复未完成」
    $('restore-result-body').innerHTML = `<div class="restore-result-ok"><div class="big">⏳</div>
      <div class="t">操作过于频繁</div>
      <div class="d">${esc(RATE_LIMIT_TEXT)}<br>当前库保持原样，等待后可重新验证和确认。</div></div>`;
  } else if (code === 'pre_backup_failed') {
    $('restore-result-body').innerHTML = `<div class="restore-result-ok"><div class="big">🛡️</div>
      <div class="t">恢复前备份未完成</div>
      <div class="d">无法创建并验证当前库的保护备份（如空间不足）。<br>
      <b>恢复已停止</b>，当前库与上一份有效备份保持原样。请释放空间后重新验证和确认。</div></div>`;
  } else if (code === 'stale_confirmation' || code === 'confirmation_expired'
             || code === 'invalid_confirmation' || code === 'migration_target_changed') {
    $('restore-result-body').innerHTML = `<div class="restore-result-ok"><div class="big">⌛</div>
      <div class="t">确认已失效</div>
      <div class="d">恢复准备期间库发生了变化或确认已过期。当前库保持原样，请重新验证备份。</div></div>`;
  } else if (code === 'committed_data_invalid') {
    $('restore-result-body').innerHTML = `<div class="restore-result-ok"><div class="big">🛑</div>
      <div class="t">恢复后数据核验异常</div>
      <div class="d">已进入保护状态并停止普通写入；当前库与操作前备份都已保留。请勿覆盖数据目录，等待处理。</div></div>`;
    setTimeout(() => { closeRestoreWizard(); forceRelock('库处于保护状态，已停止普通写入'); }, 2600);
    return;
  } else {
    $('restore-result-body').innerHTML = `<div class="restore-result-ok"><div class="big">❌</div>
      <div class="t">恢复未完成</div>
      <div class="d">${esc(msg)}<br>当前库保持原样，可重试。</div></div>`;
  }
  clearInterval(restoreCountdown); restoreCountdown = null;
  restoreStep = 4;
  renderRestoreSteps();
  ['restore-step1', 'restore-step2', 'restore-step3'].forEach((id) => $(id).classList.add('hidden'));
  $('restore-result').classList.remove('hidden');
  $('restore-next').classList.add('hidden');
  $('restore-commit').classList.add('hidden');
  $('restore-cancel').textContent = '完成';
  restoreOp = null; // 失败的操作不可重复提交
}
/* ================= AI 总开关与上云风险提示（US4/FR-015～017，对照静态稿 03） =================
   权威状态在服务端 data/settings.json（app/settings_store.py，受限 ACL、原子写），
   前端只保留内存镜像并经设置路由变更；不再使用 localStorage 死开关——
   桌面外壳随机端口导致旧偏好逐启动失效，且根本拦不住后端写入口。 */
const AI_SETTINGS_PATH = '/api/settings';
const AI_ENABLED_PATH = '/api/settings/ai-enabled';
const AI_RISK_PROMPT_PATH = '/api/settings/ai-risk-prompt';

async function loadAiSettings() {
  try {
    const data = await api(AI_SETTINGS_PATH);
    state.aiSettings = {
      aiEnabled: !!data.ai_enabled,
      riskPromptSuppressed: !!data.ai_risk_prompt_suppressed,
    };
  } catch (err) {
    // 读取失败保持安全默认（关闭外观），不阻断设置页其余功能
    state.aiSettings = { aiEnabled: false, riskPromptSuppressed: false };
    toast('加载 AI 设置失败：' + err.message, true);
  }
  renderAiSettings();
}

function renderAiSettings() {
  const { aiEnabled, riskPromptSuppressed } = state.aiSettings;
  $('ai-switch').classList.toggle('on', aiEnabled);
  const badge = $('ai-switch-badge');
  badge.classList.toggle('bad-badge', !aiEnabled);
  badge.classList.toggle('verify-badge', aiEnabled);
  badge.textContent = aiEnabled ? '已开启' : '已关闭（默认）';
  $('ai-switch-sub').textContent = aiEnabled
    ? 'AI 写入口仍须凭令牌提交，并经过锁定三态闸门与人工批准'
    : '关闭时 AI 请求一律拒绝（ai_disabled · 403），不写审批、不进队列、不触发备份';
  const riskBadge = $('ai-risk-badge');
  riskBadge.classList.toggle('verify-badge', !riskPromptSuppressed);
  riskBadge.classList.toggle('warn-badge', riskPromptSuppressed);
  riskBadge.textContent = riskPromptSuppressed ? '不再提示' : '提示生效中';
  $('ai-risk-restore').classList.toggle('hidden', !riskPromptSuppressed);
}

function applyAiSettingsResponse(data) {
  // 一切以服务端回读的两键为准，前端不自行推导偏好与开关的关系
  state.aiSettings = {
    aiEnabled: !!data.ai_enabled,
    riskPromptSuppressed: !!data.ai_risk_prompt_suppressed,
  };
  renderAiSettings();
}

async function onAiSwitchClick() {
  if (state.aiSettings.aiEnabled) {
    await disableAi();                       // 关闭免确认、即时生效
  } else if (state.aiSettings.riskPromptSuppressed) {
    await enableAiWithoutPrompt();          // 「不再提示」偏好下免确认
  } else {
    openAiRiskModal();                       // 首次开启：强制风险确认
  }
}

async function disableAi() {
  try {
    const data = await api(AI_ENABLED_PATH, { method: 'PUT', body: { enabled: false } });
    applyAiSettingsResponse(data);
    toast('AI 功能已关闭。令牌与审批历史均保留，下次开启后仍可继续使用。');
  } catch (err) {
    toast(err.message, true);  // 503 等持久化故障：本地态不翻转，仍以服务端为准
  }
}

async function enableAiWithoutPrompt() {
  try {
    const data = await api(AI_ENABLED_PATH, { method: 'PUT', body: { enabled: true } });
    applyAiSettingsResponse(data);
    toast('AI 功能已开启。');
  } catch (err) {
    toast(err.message, true);
  }
}

function openAiRiskModal() {
  $('ai-risk-confirm').checked = false;
  $('ai-risk-suppress').checked = false;
  $('ai-risk-confirm-btn').disabled = true;
  $('ai-risk-modal').classList.remove('hidden');
}

function closeAiRiskModal() {
  $('ai-risk-modal').classList.add('hidden');
  $('ai-risk-confirm').checked = false;
  $('ai-risk-suppress').checked = false;
  $('ai-risk-confirm-btn').disabled = true;
}

function toggleAiRiskConfirm() {
  // 确认勾选是「确认开启」按钮的唯一门禁
  $('ai-risk-confirm-btn').disabled = !$('ai-risk-confirm').checked;
}

function toggleAiRiskSuppress() {
  // 勾选态由原生 checkbox 自身维护；保留函数以统一事件绑定体例
}

async function submitAiEnable() {
  // 函数级再校验：未确认风险绝不发请求（与后端 409 双重保险）
  if (!$('ai-risk-confirm').checked) return;
  const suppress = $('ai-risk-suppress').checked;
  try {
    if (suppress) {
      // 偏好与开关独立存储：先落「不再提示」，再带确认开启
      await api(AI_RISK_PROMPT_PATH, { method: 'PUT', body: { suppress: true } });
    }
    const data = await api(AI_ENABLED_PATH, {
      method: 'PUT',
      body: { enabled: true, confirm_risk: true },
    });
    applyAiSettingsResponse(data);
    closeAiRiskModal();
    toast('AI 功能已开启。提交给 AI 的字段可能离开本机，请注意上云风险。');
  } catch (err) {
    // 409 risk_confirmation_required / 503：弹窗保留供用户处理，开关状态不翻转
    toast(err.message, true);
  }
}

async function restoreRiskPrompt() {
  try {
    const data = await api(AI_RISK_PROMPT_PATH, { method: 'PUT', body: { suppress: false } });
    applyAiSettingsResponse(data);
    toast('已重新开启上云风险提示，下次开启 AI 时将再次确认。');
  } catch (err) {
    toast(err.message, true);
  }
}

/* ================= 事件绑定 ================= */
$('unlock-btn').addEventListener('click', handleUnlockClick);
$('restore-entry-link').addEventListener('click', () => openRestoreWizard());
/* T037 首启两入口（FR-008）：初始化走 create PIN 流程，恢复直接开向导（空环境免会话） */
$('first-run-create').addEventListener('click', enterFirstRunCreate);
$('first-run-restore').addEventListener('click', () => openRestoreWizard());
$('first-run-back').addEventListener('click', backToFirstRun);
pinBoxes.forEach((b, i) => {
  b.addEventListener('input', () => {
    b.value = b.value.replace(/\D/g, '');
    if (b.value) { b.classList.add('filled'); if (i < 5) pinBoxes[i + 1].focus(); }
    else b.classList.remove('filled');
  });
  b.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && !b.value && i > 0) pinBoxes[i - 1].focus();
    if (e.key === 'Enter') handleUnlockClick();
  });
});

document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => switchView(t.dataset.view)));
$('lock-btn').addEventListener('click', lockApp);

$('nav').addEventListener('click', (e) => {
  const item = e.target.closest('.nav-item');
  if (item && item.dataset.cat !== undefined) {
    state.cat = item.dataset.cat;
    renderNav();
    renderList();
  }
});
$('manage-cat-btn').addEventListener('click', openCatManager);

$('list').addEventListener('click', async (e) => {
  const btn = e.target.closest('button');
  if (btn) {
    if (btn.classList.contains('eye')) { toggleSecret(btn); return; }
    if (btn.classList.contains('copy')) { await handleCopy(btn); return; }
    if (btn.classList.contains('edit-btn')) { await openEditModal(Number(btn.dataset.aid)); return; }
    if (btn.classList.contains('del-btn')) { await deleteAsset(Number(btn.dataset.aid)); return; }
  }
  const cardEl = e.target.closest('.card');
  if (cardEl && !e.target.closest('a')) cardEl.classList.toggle('open');
});

$('search').addEventListener('input', (e) => {
  state.q = e.target.value.trim().toLowerCase();
  clearTimeout(searchTimer);
  searchTimer = setTimeout(doSearch, 250);
});

$('add-asset-btn').addEventListener('click', openCreateModal);
$('modal-cancel').addEventListener('click', closeModal);
$('modal-save').addEventListener('click', saveAsset);
// 注意：故意不绑定「点遮罩关闭」——防止误点遮罩丢失未保存的输入（仅「取消」「保存」可关闭）

$('field-editor').addEventListener('click', (e) => {
  const target = e.target.closest('.fe-secret, .fe-del');
  if (!target) return;
  const i = Number(target.dataset.i);
  if (target.classList.contains('fe-secret')) {
    editFields[i].sens = !editFields[i].sens;
    editFields[i].kind = editFields[i].sens ? 'secret' : 'text';
  } else if (target.classList.contains('fe-del')) {
    editFields.splice(i, 1);
  }
  renderFieldEditor();
});
$('field-editor').addEventListener('input', (e) => {
  const row = e.target.closest('.field-edit');
  if (!row) return;
  const i = Number(row.dataset.i);
  if (e.target.classList.contains('fe-label')) editFields[i].l = e.target.value;
  if (e.target.classList.contains('fe-value')) editFields[i].v = e.target.value;
});
$('add-field-btn').addEventListener('click', () => {
  editFields.push({ l: '', v: '', sens: false, kind: 'text' });
  renderFieldEditor();
});
// US5：优先级分段切换（权威值写 hidden input）；到期日清空按钮
$('f-priority-seg').addEventListener('click', (e) => {
  const btn = e.target.closest('.seg-btn');
  if (btn) setPriorityValue(btn.dataset.priority);
});
$('f-due-clear').addEventListener('click', () => { $('f-due-date').value = ''; });

$('cat-list').addEventListener('input', (e) => {
  if (!e.target.classList.contains('cat-name')) return;
  const i = Number(e.target.closest('.cat-edit-row').dataset.i);
  editCats[i].name = e.target.value;
});
$('cat-list').addEventListener('click', (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  const i = Number(btn.dataset.i);
  if (btn.classList.contains('cat-del')) { delCatRow(i); return; }
  moveCat(i, btn.dataset.act === 'up' ? -1 : 1);
});
$('add-cat-btn').addEventListener('click', () => {
  editCats.push({ key: 'cat_' + Date.now(), name: '新分类', icon: '🏷️' });
  renderCatList();
});
$('cat-save').addEventListener('click', saveCatManager);
$('cat-cancel').addEventListener('click', closeCatManager);
$('cat-modal').addEventListener('click', (e) => { if (e.target.classList.contains('modal-mask')) closeCatManager(); });

$('req-list').addEventListener('click', async (e) => {
  const btn = e.target.closest('button');
  if (btn) {
    const id = Number(btn.dataset.id);
    if (btn.classList.contains('btn-approve')) { await approveReq(id); return; }
    if (btn.classList.contains('btn-reject')) { await rejectReq(id); return; }
  }
  const cardEl = e.target.closest('.req-card');
  if (cardEl) cardEl.classList.toggle('open');
});
$('approve-all-btn').addEventListener('click', approveAll);
$('approval-history-toggle').addEventListener('click', () => {
  const list = $('approval-history-list');
  const hidden = list.classList.toggle('hidden');
  $('approval-history-caret').textContent = hidden ? '▾' : '▴';
});

$('master-change').addEventListener('click', openPwdChange);
$('pwd-change-cancel').addEventListener('click', closePwdChange);
$('pwd-change-submit').addEventListener('click', submitPwdChange);
// 填齐门禁随输入实时更新；不绑遮罩点击与 Esc，仅「取消/保存」可关闭弹窗
PWD_CHANGE_FIELDS.forEach((id) => $(id).addEventListener('input', updatePwdChangeSubmit));
$('token-copy').addEventListener('click', copyAiToken);
$('token-reset').addEventListener('click', resetAiToken);

/* US4 AI 总开关：不绑遮罩点击与 Esc，仅「取消/确认开启」可关闭风险弹窗 */
$('ai-switch').addEventListener('click', onAiSwitchClick);
$('ai-risk-restore').addEventListener('click', restoreRiskPrompt);
$('ai-risk-confirm').addEventListener('click', toggleAiRiskConfirm);
$('ai-risk-suppress').addEventListener('click', toggleAiRiskSuppress);
$('ai-risk-cancel').addEventListener('click', closeAiRiskModal);
$('ai-risk-confirm-btn').addEventListener('click', submitAiEnable);

/* 备份与恢复视图 */
$('backup-export-btn').addEventListener('click', exportBackup);
$('goto-backup').addEventListener('click', () => switchView('backup'));
$('backup-actions').addEventListener('click', (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  if (btn.id === 'backup-retry-btn') { retryBackup(); return; }
  if (btn.id === 'backup-export-inline') exportBackup();
});
$('save-backup-banner').addEventListener('click', (e) => {
  if (e.target.closest('#retry-backup-banner-btn')) retryBackup();
});
$('backup-history-list').addEventListener('click', (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  if (btn.id === 'backup-history-more') {
    state.backupHistoryShown = 30;
    renderBackupHistory();
    return;
  }
  if (btn.classList.contains('h-download')) {
    downloadHistoryBackup(btn.dataset.id);
  }
});
$('restore-open-btn').addEventListener('click', openRestoreWizard);

/* 恢复向导 */
$('restore-choose-btn').addEventListener('click', () => $('restore-file').click());
$('restore-drop').addEventListener('click', (e) => { if (!e.target.closest('button')) $('restore-file').click(); });
$('restore-file').addEventListener('change', () => {
  const file = $('restore-file').files[0];
  if (file) {
    restoreFile = file; // 文件只在内存引用，不落盘、不缓存内容
    $('restore-file-name').textContent = file.name + '（' + Math.ceil(file.size / 1024) + ' KB）';
  }
  $('restore-file').value = '';
});
$('restore-next').addEventListener('click', () => {
  if (restoreStep === 1) prepareRestore();
  else if (restoreStep === 2) showRestoreStep3();
});
$('restore-confirm-box').addEventListener('change', setRestoreButtons);
$('restore-commit').addEventListener('click', commitRestore);
$('restore-cancel').addEventListener('click', restorePrev);
// 注意：故意不绑定「点遮罩关闭」——恢复流程中的确认与输入不因误点丢失

/* 升级兼容（T045） */
$('upgrade-open-btn').addEventListener('click', openUpgradeWizard);
$('upgrade-source-select').addEventListener('change', (e) => { upgradeSource = e.target.value; });
$('upgrade-prepare-btn').addEventListener('click', prepareUpgrade);
$('upgrade-commit-btn').addEventListener('click', commitUpgrade);
$('upgrade-retry-btn').addEventListener('click', retryUpgradeBackup);
$('upgrade-cancel').addEventListener('click', upgradeBackOrCancel);
$('upgrade-confirm-box').addEventListener('change', setUpgradeButtons);
// 注意：故意不绑定「点遮罩关闭」——核验与确认输入不因误点丢失

$('legacy-info-btn').addEventListener('click', openLegacyInfo);
$('legacy-info-close').addEventListener('click', closeLegacyInfo);
$('legacy-choose-btn').addEventListener('click', () => $('legacy-file').click());
$('legacy-file').addEventListener('change', () => {
  const file = $('legacy-file').files[0];
  if (file) onLegacyFileChosen(file); // 文件只在内存引用，不读取落盘、不缓存内容
  $('legacy-file').value = '';
});
$('legacy-convert-btn').addEventListener('click', convertLegacyMaterial);

$('rollback-open-btn').addEventListener('click', openRollback);
$('rollback-run-btn').addEventListener('click', runRollbackPreserve);
$('rollback-cancel').addEventListener('click', closeRollback);

/* 删除全部数据（T031，FR-004） */
$('wipe-open-btn').addEventListener('click', openWipeConfirm);
$('wipe-cancel').addEventListener('click', closeWipeConfirm);
$('wipe-ack').addEventListener('change', updateWipeConfirm);
$('wipe-text').addEventListener('input', updateWipeConfirm);
$('wipe-confirm').addEventListener('click', submitWipe);
// 故意不绑定「点遮罩关闭」与 Esc：危险确认只能由「取消」退出，防误触丢输入

/* ================= 库状态驱动的解锁页（T033；T037 首启两入口） ================= */
/* 桌面通道凭证经 webview loaded 事件注入，可能晚于首屏这次 state 请求；闸门对缺
 * 凭证请求回 401 channel_required。仅对此码做有界等待+重试，避免空库首启被误判成
 * 普通解锁页。浏览器入口无此闸门、永不返回该码，行为零变化、零额外等待。 */
const CHANNEL_RETRY_INTERVAL_MS = 50;
const CHANNEL_RETRY_MAX_ATTEMPTS = 30; // 总等待上限约 1.5s，超时仍按普通解锁页兜底
function waitForDesktopChannel() {
  return new Promise((resolve) => {
    if (desktopChannelToken()) return resolve();
    let attempts = 0;
    const timer = setInterval(() => {
      attempts += 1;
      if (desktopChannelToken() || attempts >= CHANNEL_RETRY_MAX_ATTEMPTS) {
        clearInterval(timer);
        resolve();
      }
    }, CHANNEL_RETRY_INTERVAL_MS);
  });
}
async function loadVaultState() {
  let data = null;
  try {
    for (let attempt = 0; attempt <= CHANNEL_RETRY_MAX_ATTEMPTS; attempt += 1) {
      const res = await desktopFetch('/api/vault/state', { headers: { Accept: 'application/json' } });
      if (res.ok) { data = await res.json(); break; }
      let code = null;
      try { code = (await res.json()).code; } catch (e) { /* 非 JSON 响应：不重试 */ }
      // 仅桌面通道专属 401 触发等待重试；其他状态码（503/403 等）维持原兜底
      if (res.status === 401 && code === 'channel_required') {
        await waitForDesktopChannel();
        continue;
      }
      break;
    }
  } catch (err) {
    data = null; // 服务未启动等场景按普通解锁页处理
  }
  state.vaultState = data;
  return state.vaultState;
}

/* FR-008：仅空环境（无库/未初始化）进首启两入口；损坏/未知库不得被当成空库 */
function isFirstRunState(vs) {
  return !!vs && (vs.state === 'missing' || vs.state === 'uninitialized');
}
function showFirstRun() {
  $('first-run').classList.remove('hidden');
  $('unlock').classList.add('hidden');
  $('app').classList.add('hidden');
}
function hideFirstRun() {
  $('first-run').classList.add('hidden');
  $('first-run-back').classList.add('hidden');
}
/* 首启「初始化新库」卡片：进入既有 create PIN 流程，提供返回两入口的链接 */
function enterFirstRunCreate() {
  hideFirstRun();
  $('unlock').classList.remove('hidden');
  setUnlockMode('create');
  $('first-run-back').classList.remove('hidden');
  resetPin();
}
/* create PIN 页返回首启两入口：清空已输入 PIN 与错误，不保留任何预选 */
function backToFirstRun() {
  resetPin();
  $('unlock-err').textContent = '';
  showFirstRun();
}

function applyVaultStateToUnlock(vs) {
  const banner = $('unlock-banner'), note = $('unlock-note');
  // 仅“无法安全打开”的状态封锁输入；旧版库允许解锁进入只读浏览
  const blockedTexts = {
    unsupported: ['暂时无法打开这个库', '检测到不支持的较新数据格式。文件保持原样，已停止写入。请使用支持该格式的程序，不要把这个库交给旧版，也不要重新初始化。'],
    corrupt: ['暂时无法打开这个库', '数据库文件无法读取或已损坏。文件保持原样，已停止写入。请不要重新初始化覆盖它；如有备份，可在恢复入口尝试恢复。'],
    maintenance_failed: ['库处于维护冻结状态', '恢复/升级后真实数据核验异常，已停止普通写入；当前库与操作前的备份都已保留，请勿覆盖本目录。'],
  };
  if (!vs) { hideFirstRun(); setUnlockMode('login'); return; }
  const s = vs.state;
  if (isFirstRunState(vs)) {
    // 空环境：两张对等卡片（初始化新库 / 从备份恢复），不直接呈现创建 PIN 卡
    showFirstRun();
    return;
  }
  hideFirstRun();
  $('restore-entry-link').classList.add('hidden');
  if (blockedTexts[s]) {
    setUnlockMode('blocked');
    $('pin-row').classList.add('hidden');
    $('unlock-btn').classList.add('hidden');
    $('unlock-err').textContent = '';
    note.classList.add('hidden');
    banner.innerHTML = `<div class="warn-banner"><b>${blockedTexts[s][0]}</b><br>${blockedTexts[s][1]}</div>`;
    banner.classList.remove('hidden');
    return;
  }
  // ready_locked / legacy_read_only：展示密码输入
  $('pin-row').classList.remove('hidden');
  $('unlock-btn').classList.remove('hidden');
  $('unlock-err').textContent = '';
  note.classList.remove('hidden');
  setUnlockMode('login');
  if (s === 'legacy_read_only') {
    // 旧版库：解锁后只读浏览，副本升级在「升级兼容」页进行（对照原型截图 10）
    banner.innerHTML = '<div class="warn-banner"><b>检测到旧版密码库</b><br>解锁后为<b>只读模式</b>，不会改动任何内容。需要升级时，请先复制一份独立副本，在「升级兼容」页核验后升级副本。</div>';
    banner.classList.remove('hidden');
  } else {
    banner.classList.add('hidden');
    banner.innerHTML = '';
  }
}

/* ================= 初始化 ================= */
async function init() {
  await loadVaultState();
  applyVaultStateToUnlock(state.vaultState);
  const saved = localStorage.getItem(TOKEN_KEY);
  if (saved) {
    state.token = saved;
    try {
      await api('/api/categories');  // 校验会话是否仍有效
      enterApp();
      return;
    } catch (err) {
      // 服务未启动时保留 token，等下次可用；会话失效则清掉
      if (!err.message.includes('无法连接后端服务')) {
        state.token = null;
        localStorage.removeItem(TOKEN_KEY);
      }
    }
  }
  resetPin();
}

init();
