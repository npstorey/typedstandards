"use client";

import { useRef } from "react";
import { ANALYTICS_API, choiceWords } from "@/lib/analytics-notice";

/**
 * The way back (IMPL TS-143; the seat's ruling 7227111427, reading 7): this
 * site has no settings surface, so the control that turns analytics off and on
 * again in this browser is on the privacy page, in its analytics section,
 * which renders only when the tag renders.
 *
 * Both states are in the served markup; `globals.css` shows the one the page's
 * analytics script set on `<html>`, before the page is first painted, and
 * shows the control only where the browser can keep the choice. "Turn
 * analytics on" loads the tag at once, so W2 is true as soon as it shows.
 */

type AnalyticsApi = { off(): boolean; on(): boolean };

function api(): AnalyticsApi | undefined {
  return (window as unknown as Record<string, AnalyticsApi | undefined>)[ANALYTICS_API];
}

const BUTTON =
  "mt-3 rounded-md border border-border bg-surface px-3 py-1.5 text-sm font-medium hover:border-accent hover:text-accent";

export function AnalyticsChoice({ holder }: { holder: string }) {
  const words = choiceWords(holder);
  const turnOn = useRef<HTMLButtonElement>(null);
  const turnOff = useRef<HTMLButtonElement>(null);
  return (
    <div data-statement="analytics-choice" className="analytics-choice rounded-md border border-border p-4">
      <div aria-live="polite">
        <p className="analytics-when-on">{words.on}</p>
        <p className="analytics-when-off">{words.off}</p>
      </div>
      <button
        type="button"
        className={`${BUTTON} analytics-when-on`}
        ref={turnOff}
        onClick={() => {
          if (api()?.off()) turnOn.current?.focus();
        }}
      >
        {words.turnOff}
      </button>
      <button
        type="button"
        className={`${BUTTON} analytics-when-off`}
        ref={turnOn}
        onClick={() => {
          if (api()?.on()) turnOff.current?.focus();
        }}
      >
        {words.turnOn}
      </button>
    </div>
  );
}
