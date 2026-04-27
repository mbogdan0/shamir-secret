import assert from "node:assert/strict";
import { test } from "node:test";
import { getElements, type UiElements } from "../src/ts/ui/dom.ts";
import { splitSharesInput } from "../src/ts/ui/forms.ts";
import { setBusy, setMessage } from "../src/ts/ui/messages.ts";
import { clearRecoveryOutput, renderRecoveryOutput } from "../src/ts/ui/recovery-output.ts";
import { renderShares } from "../src/ts/ui/shares.ts";

const REQUIRED_SELECTORS = [
  "#cryptoStatus",
  "#generateTab",
  "#recoverTab",
  "#generatePanel",
  "#recoverPanel",
  "#generateForm",
  "#recoverForm",
  "#secretInputLabel",
  "#secretHexInput",
  "#secretModeHint",
  "#secretBytes",
  "#secretTransform",
  "#generatePassphrase",
  "#recoverPassphrase",
  "#shareCount",
  "#threshold",
  "#sharesResult",
  "#shareList",
  "#recoveryScheme",
  "#recoveryMasterSecret",
  "#sharesInput",
  "#recoverResult",
  "#recoveredTextBlock",
  "#recoveredText",
  "#recoveredHexHeading",
  "#recoveredHexHelp",
  "#recoveredHex",
  "#message",
  "#copyAllShares",
  "#copyRecoveredText",
  "#copyRecovered",
  "#clearGenerate",
  "#clearRecover"
];

class FakeClassList {
  private readonly element: FakeElement;

  constructor(element: FakeElement) {
    this.element = element;
  }

  add(...names: string[]): void {
    const classes = new Set(this.element.className.split(/\s+/).filter(Boolean));
    for (const name of names) {
      classes.add(name);
    }
    this.element.className = [...classes].join(" ");
  }

  remove(...names: string[]): void {
    const classes = new Set(this.element.className.split(/\s+/).filter(Boolean));
    for (const name of names) {
      classes.delete(name);
    }
    this.element.className = [...classes].join(" ");
  }

  toggle(name: string, force?: boolean): boolean {
    const classes = new Set(this.element.className.split(/\s+/).filter(Boolean));
    const enabled = force ?? !classes.has(name);
    if (enabled) {
      classes.add(name);
    } else {
      classes.delete(name);
    }
    this.element.className = [...classes].join(" ");
    return enabled;
  }

  contains(name: string): boolean {
    return this.element.className.split(/\s+/).includes(name);
  }
}

class FakeElement {
  readonly children: FakeElement[] = [];
  readonly classList = new FakeClassList(this);
  readonly dataset: Record<string, string> = {};
  readonly listeners = new Map<string, Array<(event: unknown) => unknown>>();
  readonly style: Record<string, string> = {};
  checked = false;
  className = "";
  disabled = false;
  hidden = false;
  removed = false;
  textContent = "";
  type = "";
  value = "";

  readonly tagName: string;

  constructor(tagName: string = "div") {
    this.tagName = tagName;
  }

  append(...nodes: FakeElement[]): void {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...nodes);
  }

  addEventListener(type: string, listener: (event: unknown) => unknown): void {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  async dispatch(type: string): Promise<void> {
    for (const listener of this.listeners.get(type) ?? []) {
      await listener({ currentTarget: this, preventDefault() {} });
    }
  }

  focus(): void {}

  select(): void {}

  setSelectionRange(): void {}

  remove(): void {
    this.removed = true;
  }

  querySelectorAll(selector: string): FakeElement[] {
    const matches: FakeElement[] = [];
    const visit = (element: FakeElement): void => {
      for (const child of element.children) {
        if (selector === "button" && child.tagName === "button") {
          matches.push(child);
        }
        visit(child);
      }
    };
    visit(this);
    return matches;
  }
}

class FakeDocument {
  readonly body = new FakeElement("body");
  readonly elements = new Map<string, FakeElement>();
  readonly elementLists = new Map<string, FakeElement[]>();

  createElement(tagName: string): FakeElement {
    return new FakeElement(tagName);
  }

  querySelector(selector: string): FakeElement | null {
    return this.elements.get(selector) ?? null;
  }

  querySelectorAll(selector: string): FakeElement[] {
    return this.elementLists.get(selector) ?? [];
  }
}

function withDocument<T>(documentValue: unknown, callback: () => T): T {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: documentValue
  });

  const restore = (): void => {
    if (descriptor) {
      Object.defineProperty(globalThis, "document", descriptor);
    } else {
      Reflect.deleteProperty(globalThis, "document");
    }
  };

  try {
    const result = callback();
    if (
      result &&
      typeof result === "object" &&
      "finally" in result &&
      typeof result.finally === "function"
    ) {
      return result.finally(restore) as T;
    }
    restore();
    return result;
  } catch (error) {
    restore();
    throw error;
  }
}

function makeDocument(): FakeDocument {
  const documentValue = new FakeDocument();
  for (const selector of REQUIRED_SELECTORS) {
    documentValue.elements.set(selector, new FakeElement(selector === "#shareList" ? "ol" : "div"));
  }
  documentValue.elementLists.set("input[name='secretInputMode']", [
    new FakeElement("input"),
    new FakeElement("input")
  ]);
  return documentValue;
}

function makeElements(): UiElements {
  const documentValue = makeDocument();
  return {
    cryptoStatus: documentValue.elements.get("#cryptoStatus"),
    generateTab: documentValue.elements.get("#generateTab"),
    recoverTab: documentValue.elements.get("#recoverTab"),
    generatePanel: documentValue.elements.get("#generatePanel"),
    recoverPanel: documentValue.elements.get("#recoverPanel"),
    generateForm: documentValue.elements.get("#generateForm"),
    recoverForm: documentValue.elements.get("#recoverForm"),
    secretInputLabel: documentValue.elements.get("#secretInputLabel"),
    secretHexInput: documentValue.elements.get("#secretHexInput"),
    secretInputModes: documentValue.elementLists.get("input[name='secretInputMode']"),
    secretModeHint: documentValue.elements.get("#secretModeHint"),
    secretBytes: documentValue.elements.get("#secretBytes"),
    secretTransform: documentValue.elements.get("#secretTransform"),
    generatePassphrase: documentValue.elements.get("#generatePassphrase"),
    recoverPassphrase: documentValue.elements.get("#recoverPassphrase"),
    shareCount: documentValue.elements.get("#shareCount"),
    threshold: documentValue.elements.get("#threshold"),
    sharesResult: documentValue.elements.get("#sharesResult"),
    shareList: documentValue.elements.get("#shareList"),
    recoveryScheme: documentValue.elements.get("#recoveryScheme"),
    recoveryMasterSecret: documentValue.elements.get("#recoveryMasterSecret"),
    sharesInput: documentValue.elements.get("#sharesInput"),
    recoverResult: documentValue.elements.get("#recoverResult"),
    recoveredTextBlock: documentValue.elements.get("#recoveredTextBlock"),
    recoveredText: documentValue.elements.get("#recoveredText"),
    recoveredHexHeading: documentValue.elements.get("#recoveredHexHeading"),
    recoveredHexHelp: documentValue.elements.get("#recoveredHexHelp"),
    recoveredHex: documentValue.elements.get("#recoveredHex"),
    message: documentValue.elements.get("#message"),
    copyAllShares: documentValue.elements.get("#copyAllShares"),
    copyRecoveredText: documentValue.elements.get("#copyRecoveredText"),
    copyRecovered: documentValue.elements.get("#copyRecovered"),
    clearGenerate: documentValue.elements.get("#clearGenerate"),
    clearRecover: documentValue.elements.get("#clearRecover")
  } as unknown as UiElements;
}

test("DOM lookup returns required elements and reports missing selectors", () => {
  const documentValue = makeDocument();

  withDocument(documentValue, () => {
    const elements = getElements();
    assert.equal(elements.cryptoStatus, documentValue.elements.get("#cryptoStatus"));
    assert.equal(elements.secretInputModes.length, 2);
  });

  const missingElementDocument = makeDocument();
  missingElementDocument.elements.delete("#cryptoStatus");
  withDocument(missingElementDocument, () => {
    assert.throws(() => getElements(), /Missing required element: #cryptoStatus/);
  });

  const missingElementsDocument = makeDocument();
  missingElementsDocument.elementLists.set("input[name='secretInputMode']", []);
  withDocument(missingElementsDocument, () => {
    assert.throws(
      () => getElements(),
      /Missing required elements: input\[name='secretInputMode'\]/
    );
  });
});

test("form and message helpers normalize input and button state", () => {
  assert.deepEqual(splitSharesInput("\n first share \n\n second share\n"), [
    "first share",
    "second share"
  ]);

  const elements = makeElements();
  setMessage(elements, "Ready", "ok");
  assert.equal(elements.message.textContent, "Ready");
  assert.equal(elements.message.className, "message is-ok");
  setMessage(elements, "");
  assert.equal(elements.message.className, "message");

  const form = new FakeElement("form");
  const firstButton = new FakeElement("button");
  const secondButton = new FakeElement("button");
  form.append(firstButton, secondButton);
  setBusy(form as unknown as HTMLFormElement, true);
  assert.equal(firstButton.disabled, true);
  assert.equal(secondButton.disabled, true);
  setBusy(form as unknown as HTMLFormElement, false);
  assert.equal(firstButton.disabled, false);
});

test("recovery output rendering updates and clears text and hex fields", async () => {
  const elements = makeElements();
  const output = await renderRecoveryOutput(elements, new Uint8Array([0x54, 0x01]), {
    bytesToHex(bytes: Uint8Array): string {
      return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    },
    decodeTextMasterSecret(): string {
      return "decoded";
    }
  });

  assert.equal(output.hasText, true);
  assert.equal(elements.recoverResult.hidden, false);
  assert.equal(elements.recoveredTextBlock.hidden, false);
  assert.equal(elements.recoveredText.value, "decoded");
  assert.equal(elements.recoveredHex.value, "5401");

  clearRecoveryOutput(elements);
  assert.equal(elements.recoverResult.hidden, true);
  assert.equal(elements.recoveredTextBlock.hidden, true);
  assert.equal(elements.recoveredText.value, "");
  assert.equal(elements.recoveredHexHeading.textContent, "Recovered master secret hex");
  assert.equal(elements.recoveredHexHelp.textContent, "Recovered bytes as lowercase hex.");
  assert.equal(elements.recoveredHex.value, "");
});

test("share rendering creates copy buttons and resets previous output", async () => {
  const elements = makeElements();
  const copyCalls: string[] = [];

  await withDocument(new FakeDocument(), async () => {
    renderShares(
      elements,
      ["share one", "share two"],
      2,
      3,
      async (_button, text, copiedLabel, statusMessage) => {
        copyCalls.push(`${text}|${copiedLabel}|${statusMessage}`);
      }
    );

    assert.equal(elements.recoveryScheme.textContent, "Single group 2-of-3");
    assert.equal(elements.shareList.children.length, 2);
    assert.equal(elements.sharesResult.hidden, false);

    const shareList = elements.shareList as unknown as FakeElement;
    const firstButton = shareList.children[0].children[0].children[1];
    assert.equal(firstButton.textContent, "Copy share 1");
    await firstButton.dispatch("click");
    assert.deepEqual(copyCalls, ["share one|Copied|Copied share 1."]);

    renderShares(elements, ["new share"], 1, 1, async () => {});
    assert.equal(elements.shareList.children.length, 1);
    assert.equal(elements.recoveryScheme.textContent, "Single group 1-of-1");
  });
});
