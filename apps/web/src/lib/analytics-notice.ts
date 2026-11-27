/**
 * The analytics notice on typedstandards.org, and the reader's off (IMPL
 * TS-143, typedstandards#85).
 *
 * THE RULINGS. NA-2 B: where the service sets no cookie (Plausible), the site
 * tells, with a one-click off; the tag loads on every page until the reader
 * turns it off, then not from the next page in this browser. ND-2 A: fixed at
 * the lower left, unless a control is under it in the reader's window, then in
 * the flow at the top of `<main>`; a focused control is never under it.
 * ND-X-2 A: a hide control at every state. ND-M-2 B: the hide and the off are
 * kept six months, in the browser's own storage, never a cookie. ND-H-2 A: per
 * host. (Hub #335 7226362407 and 7226545429; the seat's ruling on the premises
 * report, typedstandards#85 7227111427.)
 *
 * THE WORDS are the reference application's ruled rows (planning
 * `temp/s4/w0/words.md` 79f8556b…, `memo2/words2.md` 0e9f5a37…), named below
 * by row, with the owner's "Full privacy page" in S52[1]'s place. A sentence
 * marked "drafted" is this site's and goes to the words check.
 *
 * THE BROWSER SCRIPT (`ANALYTICS_CHOICE_SCRIPT`) is the one implementation of
 * the memory and the place. The layout renders it after the page and before
 * the tag, so it runs before the page is interactive: it reads what this
 * browser kept, decides whether the notice shows and where, and sets that as
 * attributes on `<html>`, which `globals.css` reads. It leaves its functions
 * at `window.__typedstandardsAnalytics`, which the notice's buttons, the
 * privacy page's control, the tag's loader and its send gate call. It is kept
 * as source text so `analytics-notice.test.ts` runs the bytes the browser runs.
 */

import type { AnalyticsConfig, AnalyticsService } from './analytics.ts';

/** The browser-storage key that holds the hide and the off (W6 names it). */
export const ANALYTICS_MEMORY_KEY = 'typedstandards-analytics';

/** How long the hide and the off are kept (ND-M-2 B). */
export const MEMORY_MONTHS = 6;

/** Where the browser script leaves its functions. */
export const ANALYTICS_API = '__typedstandardsAnalytics';

/** The holder each service's words name (criterion N3: the service, not a fixed string). */
const HOLDERS: Record<AnalyticsService, string> = { plausible: 'Plausible' };

export function holderOf(config: Pick<AnalyticsConfig, 'service'>): string {
  return HOLDERS[config.service];
}

/** The notice's words. */
export function noticeWords(holder: string) {
  return {
    heading: 'Site analytics', // S145[1]
    telling: [
      // S49[1]
      `Your browser sends the address of each page you visit on this site to ${holder}, an analytics service.`,
      // S49's correction on this site, where a verify page's address is redacted
      // (premises report 7226900499, section 2). Drafted, for the words check.
      "A verify page's address is sent without the record you verify.",
    ],
    turnOff: 'Turn analytics off', // S59[1]
    hide: 'Hide this message', // S53[1]
    privacyLink: 'Full privacy page', // the owner's words, in S52[1]'s place
    off: [
      // S60[1]
      `Analytics is off in this browser. Nothing is sent to ${holder} from the next page you open.`,
      // W1, in S58's place: the way back is on the privacy page. Drafted.
      'You can change this on the privacy page.',
    ],
  };
}

/** The privacy page's control: the way back (W2, W3). */
export function choiceWords(holder: string) {
  return {
    on: 'Analytics is on in this browser.', // W2, drafted
    off: noticeWords(holder).off[0], // S60[1]
    turnOff: 'Turn analytics off', // S59[1]
    turnOn: 'Turn analytics on', // W3's button, drafted
  };
}

/**
 * THE PLACE RULE, as JavaScript: "fixed" unless a control's box overlaps the
 * notice's box by more than nothing in both directions, else "flow". Boxes are
 * at the top of the page (the first screen); an edge that only touches is not
 * under.
 */
export const NOTICE_PLACE_RULE =
  'function(box,controls){for(var i=0;i!==controls.length;i++){var c=controls[i];' +
  'if(Math.min(c.right,box.right)-Math.max(c.left,box.left)>0&&' +
  'Math.min(c.bottom,box.bottom)-Math.max(c.top,box.top)>0)return"flow"}return"fixed"}';

/** What counts as a control a reader must use: anything that can take keyboard focus. */
const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';

/**
 * THE BROWSER SCRIPT. What it keeps, under `ANALYTICS_MEMORY_KEY`, as JSON:
 * `hidden` and `off`, each the time the reader acted, as an ISO string; each
 * is read as kept for six calendar months from then, and an expired one is
 * removed when next read. Nothing else is kept, and no cookie is read or set.
 * Storage the browser refuses (a probe write throws) is read as nothing kept:
 * the off is then not offered (`data-analytics-storage="none"`), since it
 * could not be kept, and the hide hides the page in view only.
 *
 * The attributes it sets on `<html>`:
 *   data-analytics-state    "on" | "off"
 *   data-analytics-storage  "kept" | "none"
 *   data-analytics-notice   "measure" (while its box is read) | "show" | "none"
 *   data-analytics-place    "fixed" | "flow"
 *   --analytics-notice-h    the notice's height, for the foot margin
 *
 * The functions it leaves: `read()`, `place()` (run once here, and by the
 * notice on a navigation that opens a new page), `hide()`, `off()` and `on()`
 * (which loads the tag at once, through the loader `AnalyticsTags` renders).
 */
export const ANALYTICS_CHOICE_SCRIPT =
  '(function(){' +
  `var KEY=${JSON.stringify(ANALYTICS_MEMORY_KEY)},MONTHS=${MEMORY_MONTHS},root=document.documentElement;` +
  `var FOCUSABLE=${JSON.stringify(FOCUSABLE)};` +
  `var rule=${NOTICE_PLACE_RULE};` +
  'function store(){try{var s=window.localStorage,p=KEY+"-probe";s.setItem(p,"1");s.removeItem(p);return s}catch(e){return null}}' +
  'function live(at,now){if(typeof at!=="string")return false;var d=new Date(at);if(isNaN(d.getTime()))return false;' +
  'd.setUTCMonth(d.getUTCMonth()+MONTHS);return d.getTime()>now}' +
  'function load(s){var v=null;try{v=JSON.parse(s.getItem(KEY)||"null")}catch(e){v=null}' +
  'return v&&typeof v==="object"&&!Array.isArray(v)?v:{}}' +
  'function save(s,v){var kept={};if(v.hidden)kept.hidden=v.hidden;if(v.off)kept.off=v.off;' +
  'try{if(kept.hidden||kept.off)s.setItem(KEY,JSON.stringify(kept));else s.removeItem(KEY);return true}catch(e){return false}}' +
  'function current(s){var v=load(s),now=Date.now();return{hidden:live(v.hidden,now)?v.hidden:null,off:live(v.off,now)?v.off:null,raw:v}}' +
  'function read(){var s=store();if(!s)return{usable:false,hidden:false,off:false};var c=current(s);' +
  'if((c.raw.hidden!==undefined&&!c.hidden)||(c.raw.off!==undefined&&!c.off))save(s,c);' +
  'return{usable:true,hidden:!!c.hidden,off:!!c.off}}' +
  'function remember(field,value){var s=store();if(!s)return false;var c=current(s);c[field]=value;return save(s,c)}' +
  'function stamp(){return new Date(Date.now()).toISOString()}' +
  'function state(){var m=read();root.setAttribute("data-analytics-state",m.off?"off":"on");' +
  'root.setAttribute("data-analytics-storage",m.usable?"kept":"none");return m}' +
  'function notice(){return document.getElementById("analytics-notice")}' +
  'function size(n){var b=n.getBoundingClientRect();root.style.setProperty("--analytics-notice-h",b.height+"px");return b}' +
  'function place(){var m=state(),n=notice();if(!n)return;' +
  'if(m.hidden||m.off){root.setAttribute("data-analytics-notice","none");return}' +
  'root.setAttribute("data-analytics-notice","measure");var b=size(n),y=window.scrollY||0,controls=[],all=document.querySelectorAll(FOCUSABLE);' +
  'for(var i=0;i!==all.length;i++){var el=all[i];if(n.contains(el))continue;var r=el.getBoundingClientRect();' +
  'if(!r.width&&!r.height)continue;controls.push({left:r.left,right:r.right,top:r.top+y,bottom:r.bottom+y})}' +
  'root.setAttribute("data-analytics-place",rule({left:b.left,right:b.right,top:b.top,bottom:b.bottom},controls));' +
  'root.setAttribute("data-analytics-notice","show")}' +
  `window[${JSON.stringify(ANALYTICS_API)}]={read:read,place:place,` +
  'hide:function(){var ok=remember("hidden",stamp());root.setAttribute("data-analytics-notice","none");return ok},' +
  'off:function(){if(!remember("off",stamp()))return false;state();var n=notice();' +
  'if(n&&root.getAttribute("data-analytics-notice")==="show")size(n);return true},' +
  'on:function(){if(!remember("off",null))return false;state();var n=notice();' +
  'if(n&&root.getAttribute("data-analytics-notice")==="show")size(n);' +
  'if(typeof window.__typedstandardsAnalyticsLoad==="function")window.__typedstandardsAnalyticsLoad();return true}};' +
  'place()})()';
