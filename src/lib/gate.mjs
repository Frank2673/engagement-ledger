/**
 * 执行前校验门（Pre-flight Gate）
 *
 * 理念与 surface-watch 的 Scope Gate 一致，但判定维度更多：
 * 不只是"目标在不在范围内"，还要看"当前时间是否在授权窗口内"、
 * "这个动作是否被允许"。
 *
 * 设计要点：**返回完整的判定轨迹（checks）**，而不是只返回 true/false。
 * 因为审计要看的不是"当时允许了"，而是"当时依据什么允许的"——
 * 这份轨迹会被原样写进审计日志，成为可复核的证据。
 *
 * @module lib/gate
 */

import { NEVER_PERMITTED_ACTIONS, matchesScopeRule } from './manifest.mjs';

/**
 * 判定一个动作是否被授权
 *
 * @param {object} manifest 已校验的凭证
 * @param {object} input
 * @param {string} input.target 目标（域名 / IP）
 * @param {string} input.action 动作类型（如 recon / scan / manual-test）
 * @param {Date} [input.at] 动作发生时间（默认当前时间）
 * @returns {{allowed: boolean, decision: string, reason: string, checks: Array, context: object}}
 */
export function evaluateAction(manifest, { target, action, at = new Date() }) {
  const eng = manifest.engagement;
  const checks = [];

  const normalizedAction = String(action || '').trim().toLowerCase();
  const normalizedTarget = String(target || '').trim().toLowerCase().replace(/\.$/, '');
  const when = at instanceof Date ? at : new Date(at);

  const add = (name, passed, detail) => checks.push({ name, passed, detail });

  /* ---- 0. 输入完整性 ---- */
  add('input-complete', Boolean(normalizedAction && normalizedTarget), 
    normalizedAction && normalizedTarget
      ? `动作=${normalizedAction} 目标=${normalizedTarget}`
      : '动作或目标为空');

  /* ---- 1. 硬性禁止（不可通过配置放开）---- */
  const hardForbidden = NEVER_PERMITTED_ACTIONS.includes(normalizedAction);
  add(
    'action-not-hard-forbidden',
    !hardForbidden,
    hardForbidden
      ? `动作「${normalizedAction}」属于硬性禁止项 —— 任何授权都不能放行`
      : `动作「${normalizedAction}」不在硬性禁止清单内`
  );

  /* ---- 2. 凭证禁止清单 ---- */
  const prohibited = eng.prohibitedActions.includes(normalizedAction);
  add(
    'action-not-prohibited',
    !prohibited,
    prohibited
      ? `动作「${normalizedAction}」在凭证的 prohibitedActions 中`
      : '动作未被凭证列为禁止'
  );

  /* ---- 3. 允许清单（为空则不限制，仅受上面两条约束）---- */
  const hasAllowList = eng.permittedActions.length > 0;
  const permitted = !hasAllowList || eng.permittedActions.includes(normalizedAction);
  add(
    'action-permitted',
    permitted,
    hasAllowList
      ? permitted
        ? `动作「${normalizedAction}」在允许清单内`
        : `动作「${normalizedAction}」不在允许清单（${eng.permittedActions.join(', ')}）内`
      : '凭证未声明允许清单，视为不额外限制'
  );

  /* ---- 4. 时间窗 ---- */
  const win = eng.window;
  const inWindow = when.getTime() >= win.from.getTime() && when.getTime() <= win.to.getTime();
  add(
    'within-time-window',
    inWindow,
    inWindow
      ? `动作时间 ${when.toISOString()} 在授权窗口内`
      : `动作时间 ${when.toISOString()} 超出授权窗口 ${win.from.toISOString()} ~ ${win.to.toISOString()}`
  );

  /* ---- 5. 目标在范围内 ---- */
  const matchedRule = eng.scope.inScope.find((rule) => matchesScopeRule(rule, normalizedTarget));
  add(
    'target-in-scope',
    Boolean(matchedRule),
    matchedRule
      ? `目标「${normalizedTarget}」命中范围规则「${matchedRule}」`
      : `目标「${normalizedTarget}」不在 inScope 范围内`
  );

  /* ---- 6. 目标不在排除范围内（排除优先）---- */
  const excludedBy = eng.scope.outOfScope.find((rule) => matchesScopeRule(rule, normalizedTarget));
  add(
    'target-not-excluded',
    !excludedBy,
    excludedBy
      ? `目标「${normalizedTarget}」命中排除规则「${excludedBy}」—— 排除优先级高于纳入`
      : '目标未被任何排除规则命中'
  );

  const failed = checks.filter((c) => !c.passed);
  const allowed = failed.length === 0;

  return {
    allowed,
    decision: allowed ? 'allowed' : 'denied',
    /* 拒绝时把第一条失败原因作为主因（后面的检查仍完整记录在 checks 中） */
    reason: allowed
      ? `动作通过全部 ${checks.length} 项校验`
      : failed.map((c) => c.detail).join('；'),
    checks,
    context: {
      engagementId: eng.id,
      tester: eng.tester,
      action: normalizedAction,
      target: normalizedTarget,
      at: when.toISOString(),
      authorizationReference: eng.authorization.reference,
    },
  };
}
