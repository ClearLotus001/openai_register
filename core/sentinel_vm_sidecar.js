#!/usr/bin/env node
"use strict";

const nodeCrypto = require("crypto");
const { performance: nodePerformance } = require("perf_hooks");
const { runFromInputs } = require("./sdkvm");

const OPCODE = {
  SELF: 0,
  XOR_WITH_SLOT: 1,
  SET_LITERAL: 2,
  RESOLVE: 3,
  REJECT: 4,
  PUSH_OR_ADD: 5,
  GET_INDEX: 6,
  CALL: 7,
  COPY: 8,
  QUEUE: 9,
  WINDOW: 10,
  FIND_SCRIPT_MATCH: 11,
  STORE_MAP: 12,
  INVOKE: 13,
  JSON_PARSE: 14,
  JSON_STRINGIFY: 15,
  KEY: 16,
  CALL_AWAIT: 17,
  ATOB: 18,
  BTOA: 19,
  IF_EQ_CALL: 20,
  IF_ABS_GT_CALL: 21,
  WITH_QUEUE: 22,
  IF_DEFINED_CALL: 23,
  APPLY_MEMBER: 24,
  NOOP_25: 25,
  NOOP_26: 26,
  REMOVE_OR_SUB: 27,
  NOOP_28: 28,
  LT: 29,
  MAKE_CALLBACK: 30,
  MULTIPLY: 33,
  RESOLVE_PROMISE: 34,
  DIVIDE: 35,
};

function atobCompat(value) {
  return Buffer.from(String(value || ""), "base64").toString("binary");
}

function btoaCompat(value) {
  return Buffer.from(String(value || ""), "binary").toString("base64");
}

function utf8B64Json(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

function fnvHashHex(value) {
  let hashed = 2166136261;
  const text = String(value || "");
  for (let index = 0; index < text.length; index += 1) {
    hashed ^= text.charCodeAt(index);
    hashed = Math.imul(hashed, 16777619) >>> 0;
  }
  hashed ^= hashed >>> 16;
  hashed = Math.imul(hashed, 2246822507) >>> 0;
  hashed ^= hashed >>> 13;
  hashed = Math.imul(hashed, 3266489909) >>> 0;
  hashed ^= hashed >>> 16;
  return (hashed >>> 0).toString(16).padStart(8, "0");
}

function xorDecode(value, key) {
  const source = String(value || "");
  const secret = String(key || "");
  if (!secret) {
    return source;
  }
  let result = "";
  for (let index = 0; index < source.length; index += 1) {
    result += String.fromCharCode(
      source.charCodeAt(index) ^ secret.charCodeAt(index % secret.length),
    );
  }
  return result;
}

function makeStorage() {
  const store = new Map();
  return {
    length: 0,
    getItem(key) {
      return store.has(String(key)) ? store.get(String(key)) : null;
    },
    setItem(key, value) {
      store.set(String(key), String(value));
      this.length = store.size;
    },
    removeItem(key) {
      store.delete(String(key));
      this.length = store.size;
    },
    clear() {
      store.clear();
      this.length = 0;
    },
  };
}

function makeElement(tagName, extra = {}) {
  const attributes = new Map();
  return {
    tagName: String(tagName || "").toUpperCase(),
    style: {},
    children: [],
    hidden: false,
    visibility: "visible",
    ariaHidden: "false",
    innerText: "",
    textContent: "",
    src: "",
    async: false,
    defer: false,
    contentWindow: {
      postMessage() {},
      addEventListener() {},
      removeEventListener() {},
    },
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    removeChild(child) {
      this.children = this.children.filter((item) => item !== child);
      return child;
    },
    addEventListener() {},
    removeEventListener() {},
    setAttribute(name, value) {
      attributes.set(String(name), String(value));
      this[name] = value;
    },
    getAttribute(name) {
      return attributes.get(String(name)) ?? null;
    },
    getBoundingClientRect() {
      return {
        x: 0,
        y: 0,
        top: 0,
        left: 0,
        right: 84,
        bottom: 16,
        width: 84,
        height: 16,
      };
    },
    ...extra,
  };
}

function buildEnvironment(input) {
  const did = String(input.did || "").trim();
  const flow = String(input.flow || "").trim();
  const scriptSources = Array.isArray(input.script_sources) ? input.script_sources : [];
  const locationHref = String(
    input.location_href || "https://chatgpt.com/auth/login?callbackUrl=%2F&screen_hint=signup",
  );
  const navigatorLanguage = String(input.language || "en-US");
  const navigatorLanguages = Array.isArray(input.languages) && input.languages.length > 0
    ? input.languages.map((item) => String(item || ""))
    : [navigatorLanguage, "en"];
  const userAgent = String(
    input.user_agent
      || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      + "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  );
  const hardwareConcurrency = Number(input.hardware_concurrency || 8);
  const screenSum = Number(input.screen_sum || 3000);
  const screenWidth = Math.max(
    1,
    Number(input.screen_width || Math.round(screenSum * 0.64)),
  );
  const screenHeight = Math.max(
    1,
    Number(input.screen_height || Math.max(1, screenSum - screenWidth)),
  );
  const jsHeapSizeLimit = Number(input.js_heap_size_limit || 4294705152);
  const location = new URL(locationHref);
  const bodyWidth = Math.max(320, Math.min(screenWidth, 1280));
  const bodyHeight = Math.max(240, Math.min(screenHeight, 720));
  const body = makeElement("body", {
    clientWidth: bodyWidth,
    clientHeight: bodyHeight,
  });
  const head = makeElement("head");
  const documentElement = makeElement("html", {
    clientWidth: bodyWidth,
    clientHeight: bodyHeight,
  });
  documentElement.getAttribute = (name) => {
    if (name === "data-build") {
      return String(input.data_build || "prod-sidecar");
    }
    return null;
  };
  const localStorage = makeStorage();
  const history = {
    length: 2,
    state: null,
    pushState(stateValue) {
      this.state = stateValue;
    },
    replaceState(stateValue) {
      this.state = stateValue;
    },
  };
  const navigatorProto = {
    appCodeName: "Mozilla",
    appName: "Netscape",
    appVersion: "5.0",
    cookieEnabled: true,
    javaEnabled() {
      return false;
    },
    canShare() {
      return false;
    },
    onLine: true,
    pdfViewerEnabled: true,
  };
  const navigator = Object.assign(Object.create(navigatorProto), {
    userAgent,
    language: navigatorLanguage,
    languages: navigatorLanguages,
    platform: String(input.platform || "Win32"),
    vendor: String(input.vendor || "Google Inc."),
    deviceMemory: Number(input.device_memory || 8),
    maxTouchPoints: 0,
    webdriver: false,
    hardwareConcurrency,
  });
  const performanceRef = {
    memory: {
      jsHeapSizeLimit,
    },
    now() {
      return nodePerformance.now();
    },
    timeOrigin: nodePerformance.timeOrigin,
  };
  const screen = {
    width: screenWidth,
    height: screenHeight,
    availWidth: screenWidth,
    availHeight: Math.max(1, screenHeight - 40),
    availLeft: 0,
    availTop: 0,
    colorDepth: 24,
    pixelDepth: 24,
  };
  const document = {
    body,
    head,
    documentElement,
    referrer: "",
    cookie: did ? `oai-did=${encodeURIComponent(did)}` : "",
    scripts: scriptSources.map((src) => ({ src: String(src || "") })),
    currentScript: null,
    readyState: "complete",
    visibilityState: "visible",
    documentURI: location.href,
    location,
    addEventListener() {},
    removeEventListener() {},
    createElement(tagName) {
      const element = makeElement(tagName);
      element.ownerDocument = document;
      return element;
    },
  };
  document.currentScript = document.scripts[0] || null;
  const windowObject = {
    Reflect,
    Object,
    Math,
    Date,
    JSON,
    Array,
    Number,
    String,
    Boolean,
    Promise,
    URL,
    URLSearchParams,
    document,
    navigator,
    performance: performanceRef,
    screen,
    location,
    encodeURIComponent,
    decodeURIComponent,
    setTimeout,
    clearTimeout,
    parseInt,
    parseFloat,
    isFinite,
    atob: atobCompat,
    btoa: btoaCompat,
    history,
    localStorage,
    origin: location.origin,
    TextEncoder: globalThis.TextEncoder,
    __reactRouterContext: {
      state: {
        loaderData: {
          "routes/layouts/client-auth-session-layout/layout": {
            session: {
              session_id: "",
              auth_session_logging_id: "",
              openai_client_id: "",
              app_name_enum: "",
              promo: "",
              signup_source: "",
              country_code_hint: String(input.country_code_hint || "SG"),
              is_missing_session: false,
            },
            seedCacheEntry: null,
          },
        },
        actionData: null,
        errors: null,
      },
    },
    requestIdleCallback(callback) {
      return setTimeout(() => {
        callback({
          timeRemaining: () => 1,
          didTimeout: false,
        });
      }, 0);
    },
    addEventListener() {},
    removeEventListener() {},
    postMessage() {},
  };
  windowObject.window = windowObject;
  windowObject.top = windowObject;
  windowObject.self = windowObject;
  windowObject.globalThis = windowObject;
  document.defaultView = windowObject;
  return {
    did,
    flow,
    window: windowObject,
    document,
    navigator,
    performance: performanceRef,
    screen,
  };
}

function randomChoice(values, fallback = "") {
  if (!Array.isArray(values) || values.length === 0) {
    return fallback;
  }
  return values[Math.floor(Math.random() * values.length)];
}

function getBuildValue(documentRef) {
  return (
    (
      Array.from(documentRef.scripts || [])
        .map((script) => script?.src?.match("c/[^/]*/_"))
        .filter((item) => item?.length)[0] || []
    )[0]
    || documentRef.documentElement.getAttribute("data-build")
  );
}

function getNavigatorDescriptor(navigatorRef) {
  const keys = Object.keys(Object.getPrototypeOf(navigatorRef || {}));
  const key = randomChoice(keys.length > 0 ? keys : Object.keys(navigatorRef || {}), "userAgent");
  try {
    return `${key}\u2212${navigatorRef[key].toString()}`;
  } catch (_error) {
    return `${key || ""}`;
  }
}

function getConfig(env, sid) {
  const { window, document, navigator, performance, screen } = env;
  const scriptSources = Array.from(document.scripts || [])
    .map((script) => script?.src)
    .filter((value) => value);
  return [
    screen?.width + screen?.height,
    `${new Date()}`,
    performance?.memory?.jsHeapSizeLimit,
    Math?.random(),
    navigator?.userAgent,
    randomChoice(scriptSources, scriptSources[0] || ""),
    getBuildValue(document),
    navigator?.language,
    navigator?.languages?.join(","),
    Math?.random(),
    getNavigatorDescriptor(navigator),
    randomChoice(Object.keys(document), "cookie"),
    randomChoice(Object.keys(window), "location"),
    performance?.now(),
    sid,
    [...new URLSearchParams(window?.location?.search || "").keys()].join(","),
    navigator?.hardwareConcurrency,
    performance?.timeOrigin,
    Number("ai" in window),
    Number("createPRNG" in window),
    Number("cache" in window),
    Number("data" in window),
    Number("solana" in window),
    Number("dump" in window),
    Number("InstallTrigger" in window),
  ];
}

function generateRequirementsToken(env) {
  const requirementsSeed = String(Math.random());
  const sid = typeof nodeCrypto.randomUUID === "function"
    ? nodeCrypto.randomUUID()
    : `sid-${Date.now()}-${Math.random()}`;
  const candidate = getConfig(env, sid);
  const startedAt = env.performance.now();
  for (let attempt = 0; attempt < 500000; attempt += 1) {
    candidate[3] = attempt;
    candidate[9] = Math.round(env.performance.now() - startedAt);
    const encoded = utf8B64Json(candidate);
    if (fnvHashHex(requirementsSeed + encoded).substring(0, 1) <= "0") {
      return `gAAAAAC${encoded}~S`;
    }
  }
  return `gAAAAACwQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D${utf8B64Json("e")}`;
}

class BytecodeVm {
  constructor({ env, timeoutMs, timeoutMode }) {
    this.env = env;
    this.timeoutMs = timeoutMs;
    this.timeoutMode = timeoutMode;
    this.store = new Map();
    this.count = 0;
    this.chain = Promise.resolve();
    this.lastOp = null;
    this.history = [];
    this.internalErrors = [];
  }

  enqueue(task) {
    const next = this.chain.then(task, task);
    this.chain = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  async drainQueue() {
    while ((this.store.get(OPCODE.QUEUE) || []).length > 0) {
      const [op, ...args] = this.store.get(OPCODE.QUEUE).shift();
      const handler = this.store.get(op);
      this.lastOp = { op, args };
      this.history.push({ op, args });
      if (this.history.length > 25) {
        this.history.shift();
      }
      if (typeof handler !== "function") {
        throw new TypeError(`missing_handler_for_opcode_${op}`);
      }
      let value;
      try {
        value = handler(...args);
      } catch (error) {
        error.message = `[opcode=${op} count=${this.count} args=${JSON.stringify(args)}] ${error.message}`;
        throw error;
      }
      if (value && typeof value.then === "function") {
        try {
          await value;
        } catch (error) {
          error.message = `[opcode=${op} count=${this.count} args=${JSON.stringify(args)}] ${error.message}`;
          throw error;
        }
      }
      this.count += 1;
    }
  }

  installOps(settle) {
    const store = this.store;
    const env = this.env;
    const vm = this;

    store.set(OPCODE.SELF, (encoded) => vm.enqueue(() => vm.execute(encoded, { reset: false })));
    store.set(OPCODE.XOR_WITH_SLOT, (slot, otherSlot) => {
      store.set(slot, xorDecode(String(store.get(slot) ?? ""), String(store.get(otherSlot) ?? "")));
    });
    store.set(OPCODE.SET_LITERAL, (slot, value) => {
      store.set(slot, value);
    });
    store.set(OPCODE.RESOLVE, (value) => {
      settle.resolve(btoaCompat(String(value)));
    });
    store.set(OPCODE.REJECT, (value) => {
      settle.reject(btoaCompat(String(value)));
    });
    store.set(OPCODE.PUSH_OR_ADD, (slot, otherSlot) => {
      const current = store.get(slot);
      if (Array.isArray(current)) {
        current.push(store.get(otherSlot));
        return;
      }
      store.set(slot, current + store.get(otherSlot));
    });
    store.set(OPCODE.GET_INDEX, (slot, objectSlot, keySlot) => {
      store.set(slot, store.get(objectSlot)?.[store.get(keySlot)]);
    });
    store.set(OPCODE.CALL, (slot, ...argSlots) => {
      const fn = store.get(slot);
      const values = argSlots.map((argSlot) => store.get(argSlot));
      try {
        fn(...values);
      } catch (error) {
        error.message = `${error.message} [call_target_type=${typeof fn} values=${JSON.stringify(values.map((value) => {
          if (value === undefined) return "__undefined__";
          if (value === null) return null;
          if (typeof value === "function") return `__fn__:${value.name || "anonymous"}`;
          if (typeof value === "object") return `__obj__:${value.constructor?.name || "Object"}`;
          return value;
        }))}]`;
        throw error;
      }
    });
    store.set(OPCODE.COPY, (slot, otherSlot) => {
      store.set(slot, store.get(otherSlot));
    });
    store.set(OPCODE.WINDOW, env.window);
    store.set(OPCODE.FIND_SCRIPT_MATCH, (slot, patternSlot) => {
      const pattern = store.get(patternSlot);
      const matched = (
        Array.from(env.document.scripts || [])
          .map((script) => script?.src?.match(pattern))
          .filter((entry) => entry?.length)[0] || []
      )[0] ?? null;
      store.set(slot, matched);
    });
    store.set(OPCODE.STORE_MAP, (slot) => {
      store.set(slot, store);
    });
    store.set(OPCODE.INVOKE, (slot, fnSlot, ...argSlots) => {
      try {
        store.get(fnSlot)(...argSlots);
      } catch (error) {
        store.set(slot, String(error));
      }
    });
    store.set(OPCODE.JSON_PARSE, (slot, valueSlot) => {
      store.set(slot, JSON.parse(String(store.get(valueSlot) ?? "")));
    });
    store.set(OPCODE.JSON_STRINGIFY, (slot, valueSlot) => {
      store.set(slot, JSON.stringify(store.get(valueSlot)));
    });
    store.set(OPCODE.CALL_AWAIT, (slot, fnSlot, ...argSlots) => {
      const fn = store.get(fnSlot);
      const values = argSlots.map((argSlot) => store.get(argSlot));
      try {
        const result = fn(...values);
        if (result && typeof result.then === "function") {
          return result.then(
            (value) => {
              store.set(slot, value);
            },
            (error) => {
              store.set(slot, String(error));
            },
          );
        }
        store.set(slot, result);
      } catch (error) {
        error.message = `${error.message} [call_await_target_type=${typeof fn} values=${JSON.stringify(values.map((value) => {
          if (value === undefined) return "__undefined__";
          if (value === null) return null;
          if (typeof value === "function") return `__fn__:${value.name || "anonymous"}`;
          if (typeof value === "object") return `__obj__:${value.constructor?.name || "Object"}`;
          return value;
        }))}]`;
        vm.internalErrors.push({
          op: OPCODE.CALL_AWAIT,
          slot,
          fnSlot,
          argSlots,
          message: String(error.message || error),
        });
        store.set(slot, String(error));
      }
    });
    store.set(OPCODE.ATOB, (slot) => {
      store.set(slot, atobCompat(String(store.get(slot) ?? "")));
    });
    store.set(OPCODE.BTOA, (slot) => {
      store.set(slot, btoaCompat(String(store.get(slot) ?? "")));
    });
    store.set(OPCODE.IF_EQ_CALL, (leftSlot, rightSlot, fnSlot, ...argSlots) => {
      if (store.get(leftSlot) === store.get(rightSlot)) {
        return store.get(fnSlot)(...argSlots);
      }
      return null;
    });
    store.set(OPCODE.IF_ABS_GT_CALL, (leftSlot, rightSlot, thresholdSlot, fnSlot, ...argSlots) => {
      if (Math.abs(store.get(leftSlot) - store.get(rightSlot)) > store.get(thresholdSlot)) {
        return store.get(fnSlot)(...argSlots);
      }
      return null;
    });
    store.set(OPCODE.WITH_QUEUE, (slot, entries) => {
      const oldQueue = [...(store.get(OPCODE.QUEUE) || [])];
      store.set(OPCODE.QUEUE, [...entries]);
      return vm.drainQueue().then(
        (value) => {
          store.set(slot, String(value));
        },
        (error) => {
          store.set(slot, String(error));
        },
      ).finally(() => {
        store.set(OPCODE.QUEUE, oldQueue);
      });
    });
    store.set(OPCODE.IF_DEFINED_CALL, (slot, fnSlot, ...argSlots) => {
      if (store.get(slot) !== undefined) {
        return store.get(fnSlot)(...argSlots);
      }
      return null;
    });
    store.set(OPCODE.APPLY_MEMBER, (slot, objectSlot, memberSlot) => {
      const objectValue = store.get(objectSlot);
      const memberName = store.get(memberSlot);
      try {
        store.set(slot, objectValue[memberName].bind(objectValue));
      } catch (error) {
        error.message = `${error.message} [apply_member_object=${objectValue === undefined ? "__undefined__" : (objectValue?.constructor?.name || typeof objectValue)} member=${String(memberName)}]`;
        throw error;
      }
    });
    store.set(OPCODE.NOOP_25, () => {});
    store.set(OPCODE.NOOP_26, () => {});
    store.set(OPCODE.REMOVE_OR_SUB, (slot, otherSlot) => {
      const current = store.get(slot);
      if (Array.isArray(current)) {
        const index = current.indexOf(store.get(otherSlot));
        if (index >= 0) {
          current.splice(index, 1);
        }
        return;
      }
      store.set(slot, current - store.get(otherSlot));
    });
    store.set(OPCODE.NOOP_28, () => {});
    store.set(OPCODE.LT, (slot, leftSlot, rightSlot) => {
      store.set(slot, store.get(leftSlot) < store.get(rightSlot));
    });
    store.set(OPCODE.MAKE_CALLBACK, (slot, resultSlot, argBindingSlots, nestedQueueSlots) => {
      const hasArgBinding = Array.isArray(nestedQueueSlots);
      const boundSlots = hasArgBinding ? argBindingSlots : [];
      const nextQueue = (hasArgBinding ? nestedQueueSlots : argBindingSlots) || [];
      store.set(slot, (...callbackArgs) => {
        if (settle.finished) {
          return undefined;
        }
        const oldQueue = [...(store.get(OPCODE.QUEUE) || [])];
        if (hasArgBinding) {
          for (let index = 0; index < boundSlots.length; index += 1) {
            store.set(boundSlots[index], callbackArgs[index]);
          }
        }
        store.set(OPCODE.QUEUE, [...nextQueue]);
        return vm.drainQueue()
          .then(() => store.get(resultSlot))
          .then((value) => String(value))
          .finally(() => {
            store.set(OPCODE.QUEUE, oldQueue);
          });
      });
    });
    store.set(OPCODE.MULTIPLY, (slot, leftSlot, rightSlot) => {
      store.set(slot, Number(store.get(leftSlot)) * Number(store.get(rightSlot)));
    });
    store.set(OPCODE.RESOLVE_PROMISE, (slot, valueSlot) => {
      try {
        return Promise.resolve(store.get(valueSlot)).then((value) => {
          store.set(slot, value);
        });
      } catch (_error) {
        return undefined;
      }
    });
    store.set(OPCODE.DIVIDE, (slot, leftSlot, rightSlot) => {
      const leftValue = Number(store.get(leftSlot));
      const rightValue = Number(store.get(rightSlot));
      store.set(slot, rightValue === 0 ? 0 : leftValue / rightValue);
    });
  }

  execute(encoded, { key, reset }) {
    return this.enqueue(() => new Promise((resolve, reject) => {
      if (reset) {
        this.store.clear();
        this.count = 0;
      }
      if (key !== undefined) {
        this.store.set(OPCODE.KEY, key);
      }

      const settle = {
        finished: false,
        resolve: (value) => {
          if (settle.finished) {
            return;
          }
          settle.finished = true;
          clearTimeout(timer);
          resolve(value);
        },
        reject: (value) => {
          if (settle.finished) {
            return;
          }
          settle.finished = true;
          clearTimeout(timer);
          reject(value);
        },
      };

      this.installOps(settle);

      const timer = setTimeout(() => {
        if (settle.finished) {
          return;
        }
        settle.finished = true;
        if (this.timeoutMode === "raw_count") {
          resolve(String(this.count));
        } else {
          reject(new Error("session_observer_vm_timeout"));
        }
      }, this.timeoutMs);

      try {
        const program = JSON.parse(
          xorDecode(atobCompat(encoded), String(this.store.get(OPCODE.KEY) ?? "")),
        );
        this.store.set(OPCODE.QUEUE, program);
        this.drainQueue()
          .then((value) => {
            settle.resolve(btoaCompat(`${this.count}: ${value}`));
          })
          .catch((error) => {
            settle.resolve(btoaCompat(`${this.count}: ${error}`));
          });
      } catch (error) {
        settle.resolve(btoaCompat(`${this.count}: ${error}`));
      }
    }));
  }
}

async function runSidecar(input) {
  const env = buildEnvironment(input);
  if (input && input.mode === "requirements") {
    return {
      ok: true,
      requirements_token: generateRequirementsToken(env),
    };
  }
  const payload = input && typeof input.payload === "object" && input.payload ? input.payload : {};
  const turnstile = payload.turnstile && typeof payload.turnstile === "object" ? payload.turnstile : {};
  const so = payload.so && typeof payload.so === "object" ? payload.so : {};
  const requirementsToken = String(input.requirements_token || "");
  const proof = String(input.proof || "");
  const flow = String(input.flow || env.flow || "");
  const did = String(input.did || env.did || "");

  const result = {
    ok: true,
    turnstile_t: "",
    turnstile_error: "",
    session_observer_raw: "",
    session_observer_error: "",
    openai_sentinel_token: "",
    openai_sentinel_so_token: "",
    debug: {},
  };

  try {
    if (turnstile && turnstile.dx && requirementsToken) {
      const turnstileRun = await runFromInputs(requirementsToken, String(turnstile.dx), {
        windowRef: env.window,
        documentRef: env.document,
        timeoutMs: 2000,
      });
      result.debug.turnstile_vm = turnstileRun;
      result.turnstile_t = String(turnstileRun?.encodedValue || "").trim();
      if (!result.turnstile_t && turnstileRun && turnstileRun.value) {
        result.turnstile_error = String(turnstileRun.value);
      }
    }
  } catch (error) {
    result.turnstile_error = String(error);
  }

  try {
    if (so && so.required && so.collector_dx && so.snapshot_dx && requirementsToken) {
      const sessionVm = new BytecodeVm({
        env,
        timeoutMs: 60000,
        timeoutMode: "reject",
      });
      await sessionVm.execute(String(so.collector_dx), {
        key: requirementsToken,
        reset: true,
      });
      result.debug.collector_last_op = sessionVm.lastOp;
      result.debug.collector_history = sessionVm.history;
      result.session_observer_raw = await sessionVm.execute(String(so.snapshot_dx), {
        reset: false,
      });
      result.debug.snapshot_last_op = sessionVm.lastOp;
      result.debug.snapshot_history = sessionVm.history;
      result.debug.snapshot_internal_errors = sessionVm.internalErrors;
    }
  } catch (error) {
    result.session_observer_error = String(error);
  }

  if (proof && payload.token && flow && did) {
    result.openai_sentinel_token = JSON.stringify({
      p: proof,
      t: result.turnstile_t || "",
      c: String(payload.token || ""),
      id: did,
      flow,
    });
  }
  if (result.session_observer_raw && payload.token && flow && did) {
    result.openai_sentinel_so_token = JSON.stringify({
      so: result.session_observer_raw,
      c: String(payload.token || ""),
      id: did,
      flow,
    });
  }
  return result;
}

async function main() {
  const raw = await new Promise((resolve, reject) => {
    let buffer = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      buffer += chunk;
    });
    process.stdin.on("end", () => resolve(buffer));
    process.stdin.on("error", reject);
  });
  const input = raw.trim() ? JSON.parse(raw) : {};
  const output = await runSidecar(input);
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${String(error && error.stack ? error.stack : error)}\n`);
    process.exit(1);
  });
}

module.exports = {
  runSidecar,
};
