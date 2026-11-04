/**
 * 网易易盾滑块人机验证集成模块
 * 对应酷安官方 APK 中的 NetEaseProtectSDKManager / wn.java 逻辑
 */

import { logDiagnostic, summarizeDiagnosticError } from './diagnosticLogger';

declare global {
  interface Window {
    initNECaptcha?: (
      config: NECaptchaConfig,
      onload?: (instance: NECaptchaInstance) => void,
      onerror?: (err: any) => void
    ) => void;
  }
}

export interface NECaptchaConfig {
  captchaId: string;
  element?: string | HTMLElement;
  mode?: 'float' | 'embed' | 'popup';
  apiVersion?: 2;
  width?: string | number;
  lang?: string;
  onReady?: (instance: NECaptchaInstance) => void;
  onVerify?: (err: any, data: { validate?: string; [key: string]: any }) => void;
  onClose?: () => void;
  [key: string]: any;
}

export interface NECaptchaInstance {
  verify: () => void;
  refresh: () => void;
  destroy: () => void;
}

/** 酷安官方网易易盾 Captcha ID */
export const DEFAULT_COOLAPK_CAPTCHA_ID = '414e5c9b866a03db03f860a1a9101672';

/**
 * 从酷安服务端响应中解析动态下发的 Captcha 配置（对应 APK C2143.java / wn.java）
 */
export function extractCaptchaParamsFromResponse(data: any): { captchaId?: string; captchaField?: string } | null {
  if (!data) return null;
  let extraStr = data.messageExtra || data.extra;
  if (!extraStr && typeof data === 'object') {
    if (data.captchaId) {
      return {
        captchaId: data.captchaId,
        captchaField: typeof data.captchaField === 'string' ? data.captchaField : '_v2_post_token',
      };
    }
  }
  if (typeof extraStr === 'string' && extraStr.trim().startsWith('{')) {
    try {
      const obj = JSON.parse(extraStr);
      if (obj.captchaId) {
        return {
          captchaId: obj.captchaId,
          // captchaField 显式为空表示 validate-cookie 协议，必须保留空串让原生层选择通道。
          captchaField: typeof obj.captchaField === 'string' ? obj.captchaField : '_v2_post_token',
        };
      }
    } catch (e) {
      // ignore
    }
  }
  return null;
}

/** 从原生接口抛出的验证码响应中提取配置，兼容服务端只返回 code=403 的情况。 */
export function extractCaptchaParamsFromError(error: unknown): { captchaId: string; captchaField: string } | null {
  let response: any = error instanceof Error ? error.message : error;
  if (typeof response === 'string') {
    try { response = JSON.parse(response); } catch { return null; }
  }
  if (!response || typeof response !== 'object') return null;
  const params = extractCaptchaParamsFromResponse(response);
  if (params?.captchaId) {
    return {
      captchaId: params.captchaId,
      // 空串表示 validate-cookie 协议，不能折叠成默认字段名。
      captchaField: typeof params.captchaField === 'string' ? params.captchaField : '_v2_post_token',
    };
  }
  const reason = [response.messageStatus, response.message, response.error].filter((value) => typeof value === 'string').join(' ');
  if (Number(response.code) === 403 && /(captcha|验证码)/i.test(reason)) {
    return { captchaId: DEFAULT_COOLAPK_CAPTCHA_ID, captchaField: '_v2_post_token' };
  }
  return null;
}

let scriptLoadingPromise: Promise<void> | null = null;
const SCRIPT_LOAD_TIMEOUT_MS = 15_000;

/** 单个验证码会话的总超时：弹窗长时间无人操作时释放调用方，避免"正在加载全文..."永久挂起。 */
const VERIFY_TIMEOUT_MS = 180_000;

/** 全局进行中的验证会话：同一 captchaId 共享等待，避免多次触发堆叠出多个弹窗。 */
let activeVerification: { captchaId: string; promise: Promise<string> } | null = null;

/**
 * 动态加载网易易盾 Web JS SDK
 */
export function loadNECaptchaScript(): Promise<void> {
  if (typeof window === 'undefined') {
    return Promise.reject(new Error('易盾验证码只能在浏览器环境运行'));
  }
  if (window.initNECaptcha) {
    return Promise.resolve();
  }
  if (scriptLoadingPromise) {
    return scriptLoadingPromise;
  }

  scriptLoadingPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>('script[src*="cstaticdun.126.net/load.min.js"]');
    const script = existing || document.createElement('script');
    let settled = false;
    // 旧标签可能已经触发过事件，统一设置超时，避免永远占用全文请求槽。
    const timeout = window.setTimeout(() => fail(new Error('网易易盾验证码脚本加载超时')), SCRIPT_LOAD_TIMEOUT_MS);
    const cleanup = () => {
      window.clearTimeout(timeout);
      script.removeEventListener('load', onLoad);
      script.removeEventListener('error', onError);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      // 失败标签必须移除，下次调用才会发起新的脚本请求。
      script.remove();
      reject(error);
    };
    const onLoad = () => {
      if (settled) return;
      if (!window.initNECaptcha) {
        fail(new Error('网易易盾初始化函数不可用'));
        return;
      }
      settled = true;
      cleanup();
      resolve();
    };
    const onError = () => fail(new Error('网易易盾验证码脚本加载失败'));
    script.addEventListener('load', onLoad);
    script.addEventListener('error', onError);
    if (!existing) {
      script.src = 'https://cstaticdun.126.net/load.min.js';
      script.async = true;
      script.charset = 'utf-8';
      document.head.appendChild(script);
    }
  }).then(() => {
    scriptLoadingPromise = null;
  }, (error) => {
    scriptLoadingPromise = null;
    throw error;
  });

  return scriptLoadingPromise;
}

/**
 * 唤起网易易盾滑块弹窗并完成验证
 * @param captchaId 易盾业务 ID，默认使用酷安官方 ID
 * @returns 返回拼装后的官方标准 Token，格式为 `NEC:{captchaId前8位}:{validate}`
 */
export async function verifyWithCaptcha(captchaId = DEFAULT_COOLAPK_CAPTCHA_ID): Promise<string> {
  // 并发触发时（如连续展开多条动态）复用同一弹窗会话，避免堆叠多个验证码。
  if (activeVerification) {
    if (activeVerification.captchaId === captchaId) {
      logDiagnostic('info', 'captcha', 'verify_joined', `captcha_id=${captchaId}`);
      return activeVerification.promise;
    }
    logDiagnostic('warn', 'captcha', 'verify_busy', `captcha_id=${captchaId} active_id=${activeVerification.captchaId}`);
    throw new Error('已有其他验证码正在进行，请先完成当前验证');
  }

  const promise = runVerification(captchaId);
  activeVerification = { captchaId, promise };
  try {
    return await promise;
  } finally {
    if (activeVerification?.promise === promise) {
      activeVerification = null;
    }
  }
}

/** 采样验证码弹窗相关 DOM 的几何与可见性，用于诊断"弹窗已创建但不可见"的问题。 */
function describeCaptchaDom(captchaId: string): string {
  const nodes = Array.from(
    document.body.querySelectorAll<HTMLElement>('[class*="yidun"], iframe[src*="dun.163"], iframe[src*="126.net"]'),
  ).slice(0, 6);
  const parts = nodes.map((el) => {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    const cls = typeof el.className === 'string' && el.className ? el.className.slice(0, 40) : el.tagName.toLowerCase();
    const src = el instanceof HTMLIFrameElement && el.src ? ` src=${summarizeDiagnosticError(el.src)}` : '';
    return `${el.tagName.toLowerCase()}.${cls}@${Math.round(rect.width)}x${Math.round(rect.height)} pos=${Math.round(rect.left)},${Math.round(rect.top)} display=${style.display} visibility=${style.visibility}${src}`;
  });
  return `captcha_id=${captchaId} viewport=${window.innerWidth}x${window.innerHeight} nodes=${parts.length ? parts.join(' | ') : 'none'}`;
}

/** 创建弹窗会话并等待用户完成验证；成功返回 NEC token，取消/失败/超时则 reject。 */
async function runVerification(captchaId: string): Promise<string> {
  await loadNECaptchaScript();

  if (!window.initNECaptcha) {
    throw new Error('网易易盾初始化函数不可用');
  }

  return new Promise<string>((resolve, reject) => {
    // 挂载容器必须自身占满视口：SDK 会把弹窗子树锚定在容器原点/容器内布局，
    // 空容器（文档流末尾）会把整个弹窗排到视口底边之外导致"弹窗不可见"。
    const container = document.createElement('div');
    container.id = `ne-captcha-${Date.now()}`;
    container.style.position = 'fixed';
    container.style.top = '0';
    container.style.left = '0';
    container.style.width = '100%';
    container.style.height = '100%';
    container.style.zIndex = '99999';
    document.body.appendChild(container);

    let captchaInstance: NECaptchaInstance | null = null;
    let resolved = false;

    // 兜底居中：无论 SDK 用何种定位策略，把弹窗主体拉回视口中心。
    const centerPopup = () => {
      if (resolved) return;
      const popup = container.querySelector<HTMLElement>('.yidun_popup');
      if (!popup) return;
      const rect = popup.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      if (rect.top >= 0 && rect.left >= 0 && rect.bottom <= window.innerHeight && rect.right <= window.innerWidth) return;
      popup.style.position = 'fixed';
      popup.style.top = `${Math.max(0, Math.round((window.innerHeight - rect.height) / 2))}px`;
      popup.style.left = `${Math.max(0, Math.round((window.innerWidth - rect.width) / 2))}px`;
      popup.style.transform = 'none';
    };

    const cleanup = () => {
      window.clearTimeout(timeoutId);
      try {
        if (captchaInstance) {
          captchaInstance.destroy();
        }
      } catch (e) {
        // ignore
      }
      if (container.parentNode) {
        container.parentNode.removeChild(container);
      }
    };

    const timeoutId = window.setTimeout(() => {
      if (resolved) return;
      resolved = true;
      logDiagnostic('warn', 'captcha', 'verify_timeout', `captcha_id=${captchaId} elapsed_ms=${VERIFY_TIMEOUT_MS}`);
      cleanup();
      reject(new Error('验证码验证超时，请重试'));
    }, VERIFY_TIMEOUT_MS);

    window.initNECaptcha!(
      {
        captchaId,
        element: container,
        mode: 'popup',
        apiVersion: 2,
        width: '320px',
        lang: 'zh-CN',
        onReady: (instance) => {
          captchaInstance = instance;
        },
        onVerify: (err, data) => {
          if (err) {
            resolved = true;
            logDiagnostic('warn', 'captcha', 'verify_failed', `captcha_id=${captchaId} reason=${summarizeDiagnosticError(err)}`);
            cleanup();
            reject(new Error(typeof err === 'string' ? err : err?.message || '验证码验证失败'));
            return;
          }
          if (data && data.validate) {
            resolved = true;
            logDiagnostic('info', 'captcha', 'verify_succeeded', `captcha_id=${captchaId}`);
            const prefix = captchaId.slice(0, 8);
            const token = `NEC:${prefix}:${data.validate}`;
            cleanup();
            resolve(token);
          } else {
            resolved = true;
            logDiagnostic('warn', 'captcha', 'verify_failed', `captcha_id=${captchaId} reason=empty_validate`);
            cleanup();
            reject(new Error('验证码凭证无效'));
          }
        },
        onClose: () => {
          if (!resolved) {
            resolved = true;
            logDiagnostic('info', 'captcha', 'verify_cancelled', `captcha_id=${captchaId}`);
            cleanup();
            reject(new Error('用户取消了人机验证'));
          }
        },
      },
      (instance) => {
        captchaInstance = instance;
        if (typeof instance.verify !== 'function') {
          resolved = true;
          cleanup();
          reject(new Error('易盾验证码实例不支持弹出验证'));
          return;
        }
        try {
          instance.verify();
          logDiagnostic('info', 'captcha', 'popup_shown', `captcha_id=${captchaId}`);
          window.setTimeout(centerPopup, 400);
          window.setTimeout(centerPopup, 1000);
          // 延迟采样一次几何信息，确认弹窗落在视口内，便于排查"弹窗不可见"类问题。
          window.setTimeout(() => {
            if (resolved) return;
            logDiagnostic('info', 'captcha', 'popup_geometry', describeCaptchaDom(captchaId));
          }, 1500);
        } catch (error) {
          resolved = true;
          logDiagnostic('warn', 'captcha', 'popup_failed', `captcha_id=${captchaId} reason=${summarizeDiagnosticError(error)}`);
          cleanup();
          reject(error instanceof Error ? error : new Error('唤起易盾验证码失败'));
        }
      },
      (err) => {
        logDiagnostic('warn', 'captcha', 'init_failed', `captcha_id=${captchaId} reason=${summarizeDiagnosticError(err)}`);
        cleanup();
        reject(new Error(typeof err === 'string' ? err : err?.message || '初始化易盾滑块失败'));
      }
    );
  });
}
