"use client";

import { useLayoutEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import { ANALYTICS_API, noticeWords } from "@/lib/analytics-notice";

/**
 * The analytics notice (IMPL TS-143; NA-2 B, ND-2 A, ND-X-2 A). The layout
 * renders it at the top of `<main>`, only when the tag renders. It is in the
 * served markup with both of its states, and shows nothing until the page's
 * analytics script (`ANALYTICS_CHOICE_SCRIPT`) has read this browser's memory
 * and set its state and place on `<html>`; `globals.css` shows the state and
 * the place from those attributes. So the notice takes its place before the
 * page is first painted, and a hidden notice never flashes.
 *
 * Its buttons call that script: "Turn analytics off" keeps the off and turns
 * the notice to its off state (S60, W1); "Hide this message" keeps the hide.
 * The off button shows only while analytics is on, and only where the browser
 * can keep the off.
 *
 * A NAVIGATION THAT OPENS A NEW PAGE without a reload re-runs the place before
 * the new page paints, so the rule is read for each page. An address change
 * that opens no new page (the verifier writes its result's address with
 * `replaceState`) does not: the page's root element is the same node, and
 * moving the notice then would move what the reader sees.
 */

type AnalyticsApi = { hide(): boolean; off(): boolean; place(): void };

function api(): AnalyticsApi | undefined {
  return (window as unknown as Record<string, AnalyticsApi | undefined>)[ANALYTICS_API];
}

const BUTTON =
  "rounded-md border border-border bg-surface px-3 py-1.5 text-sm font-medium hover:border-accent hover:text-accent";

export function AnalyticsNotice({ holder }: { holder: string }) {
  const words = noticeWords(holder);
  const hideButton = useRef<HTMLButtonElement>(null);
  const pageRoot = useRef<Element | null | undefined>(undefined);
  const pathname = usePathname();

  useLayoutEffect(() => {
    const notice = document.getElementById("analytics-notice");
    const main = notice?.parentElement;
    const root = main ? Array.from(main.children).find((child) => child !== notice) ?? null : null;
    if (pageRoot.current === undefined || root === pageRoot.current) {
      pageRoot.current = root;
      return;
    }
    pageRoot.current = root;
    api()?.place();
  }, [pathname]);

  return (
    <aside id="analytics-notice" className="analytics-notice" aria-labelledby="analytics-notice-heading">
      <div className="analytics-notice-card">
        <h2 id="analytics-notice-heading" className="font-display text-base font-semibold tracking-tight">
          {words.heading}
        </h2>
        <div aria-live="polite">
          <div className="analytics-when-on">
            {words.telling.map((sentence) => (
              <p key={sentence} className="mt-2">
                {sentence}
              </p>
            ))}
          </div>
          <div className="analytics-when-off">
            {words.off.map((sentence) => (
              <p key={sentence} className="mt-2">
                {sentence}
              </p>
            ))}
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button
            type="button"
            className={`${BUTTON} analytics-when-on analytics-needs-storage`}
            onClick={() => {
              if (api()?.off()) hideButton.current?.focus();
            }}
          >
            {words.turnOff}
          </button>
          <button type="button" className={BUTTON} ref={hideButton} onClick={() => api()?.hide()}>
            {words.hide}
          </button>
        </div>
        <a href="/privacy" className="mt-3 inline-block text-sm underline decoration-dotted hover:text-accent">
          {words.privacyLink}
        </a>
      </div>
    </aside>
  );
}
