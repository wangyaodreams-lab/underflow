// A bounded log view that follows the tail of the server's output.

const MAX_LINES = 5000;

export interface LogView {
  root: HTMLElement;
  append(seq: number, text: string): void;
  clear(): void;
  setAutoscroll(on: boolean): void;
}

export function buildLogView(): LogView {
  const root = document.createElement("div");
  root.className = "logs";

  const output = document.createElement("pre");
  output.className = "log-output";
  root.append(output);

  let autoscroll = true;
  let lastSeq = 0;

  // Turning autoscroll off should only happen for deliberate scrolling up.
  output.addEventListener("scroll", () => {
    const atBottom = output.scrollTop + output.clientHeight >= output.scrollHeight - 24;
    if (!atBottom) autoscroll = false;
  });

  function trim() {
    while (output.childElementCount > MAX_LINES) {
      output.firstElementChild?.remove();
    }
  }

  return {
    root,
    append(seq, text) {
      if (seq && seq <= lastSeq) return;
      if (seq) lastSeq = seq;
      const line = document.createElement("span");
      line.className = "log-line";
      if (/^error:|\bfail(ed|ure)?\b/i.test(text)) line.classList.add("log-error");
      else if (/\bwarn(ing)?\b/i.test(text)) line.classList.add("log-warn");
      line.textContent = text + "\n";
      const stick = autoscroll;
      output.append(line);
      trim();
      if (stick) output.scrollTop = output.scrollHeight;
    },
    clear() {
      output.replaceChildren();
      lastSeq = 0;
    },
    setAutoscroll(on) {
      autoscroll = on;
      if (on) output.scrollTop = output.scrollHeight;
    },
  };
}
