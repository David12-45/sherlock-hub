/**
 * Browser-native OSINT engines for GitHub Pages / static mode.
 * Queries strictly public, CORS-enabled open APIs directly from the browser
 * (zero server required) and supports client-side export & localStorage history.
 */
(() => {
  "use strict";

  const PROVIDER_HINTS = {
    "google.com": "Google / Google Workspace",
    "googlemail.com": "Google / Gmail",
    "outlook.com": "Microsoft 365 / Outlook",
    "protection.outlook.com": "Microsoft 365 / Exchange Online",
    "yandex.net": "Yandex Mail / Yandex 360",
    "yandex.ru": "Yandex Mail",
    "mail.ru": "VK Mail (Mail.ru)",
    "protonmail.ch": "Proton Mail",
    "proton.me": "Proton Mail",
    "icloud.com": "Apple iCloud Mail",
    "yahoodns.net": "Yahoo Mail",
    "messagingengine.com": "Fastmail",
    "zoho.com": "Zoho Mail",
    "cloudflare.net": "Cloudflare Email Routing",
    "migadu.com": "Migadu",
    "tutanota.de": "Tuta Mail",
  };

  const DISPOSABLE_DOMAINS = new Set([
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "yopmail.com", "throwawaymail.com", "sharklasers.com", "trashmail.com",
    "getnada.com", "temp-mail.org", "dispostable.com",
  ]);

  const PUBLIC_MAIL_DOMAINS = new Set([
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "me.com", "yandex.ru", "ya.ru", "mail.ru",
    "bk.ru", "inbox.ru", "list.ru", "proton.me", "protonmail.com",
  ]);

  const COUNTRY_CODES = [
    ["1", "США / Канада (NANP)", "America/New_York … America/Los_Angeles"],
    ["7", "Россия / Казахстан", "Europe/Moscow … Asia/Almaty"],
    ["20", "Египет", "Africa/Cairo"],
    ["27", "ЮАР", "Africa/Johannesburg"],
    ["30", "Греция", "Europe/Athens"],
    ["31", "Нидерланды", "Europe/Amsterdam"],
    ["32", "Бельгия", "Europe/Brussels"],
    ["33", "Франция", "Europe/Paris"],
    ["34", "Испания", "Europe/Madrid"],
    ["36", "Венгрия", "Europe/Budapest"],
    ["39", "Италия", "Europe/Rome"],
    ["40", "Румыния", "Europe/Bucharest"],
    ["41", "Швейцария", "Europe/Zurich"],
    ["43", "Австрия", "Europe/Vienna"],
    ["44", "Великобритания", "Europe/London"],
    ["45", "Дания", "Europe/Copenhagen"],
    ["46", "Швеция", "Europe/Stockholm"],
    ["47", "Норвегия", "Europe/Oslo"],
    ["48", "Польша", "Europe/Warsaw"],
    ["49", "Германия", "Europe/Berlin"],
    ["52", "Мексика", "America/Mexico_City"],
    ["54", "Аргентина", "America/Argentina/Buenos_Aires"],
    ["55", "Бразилия", "America/Sao_Paulo"],
    ["60", "Малайзия", "Asia/Kuala_Lumpur"],
    ["61", "Австралия", "Australia/Sydney"],
    ["62", "Индонезия", "Asia/Jakarta"],
    ["63", "Филиппины", "Asia/Manila"],
    ["64", "Новая Зеландия", "Pacific/Auckland"],
    ["65", "Сингапур", "Asia/Singapore"],
    ["66", "Таиланд", "Asia/Bangkok"],
    ["81", "Япония", "Asia/Tokyo"],
    ["82", "Южная Корея", "Asia/Seoul"],
    ["84", "Вьетнам", "Asia/Ho_Chi_Minh"],
    ["86", "Китай", "Asia/Shanghai"],
    ["90", "Турция", "Europe/Istanbul"],
    ["91", "Индия", "Asia/Kolkata"],
    ["92", "Пакистан", "Asia/Karachi"],
    ["98", "Иран", "Asia/Tehran"],
    ["351", "Португалия", "Europe/Lisbon"],
    ["353", "Ирландия", "Europe/Dublin"],
    ["358", "Финляндия", "Europe/Helsinki"],
    ["370", "Литва", "Europe/Vilnius"],
    ["371", "Латвия", "Europe/Riga"],
    ["372", "Эстония", "Europe/Tallinn"],
    ["373", "Молдова", "Europe/Chisinau"],
    ["374", "Армения", "Asia/Yerevan"],
    ["375", "Беларусь", "Europe/Minsk"],
    ["380", "Украина", "Europe/Kyiv"],
    ["381", "Сербия", "Europe/Belgrade"],
    ["420", "Чехия", "Europe/Prague"],
    ["421", "Словакия", "Europe/Bratislava"],
    ["971", "ОАЭ", "Asia/Dubai"],
    ["972", "Израиль", "Asia/Jerusalem"],
    ["992", "Таджикистан", "Asia/Dushanbe"],
    ["994", "Азербайджан", "Asia/Baku"],
    ["995", "Грузия", "Asia/Tbilisi"],
    ["996", "Кыргызстан", "Asia/Bishkek"],
    ["998", "Узбекистан", "Asia/Tashkent"],
  ].sort((a, b) => b[0].length - a[0].length);

  // Curated direct-check templates from Sherlock / Maigret for sites whose HTML is blocked by browser CORS
  const CURATED_QUICK_LINKS = [
    ["Telegram", "social", (u) => `https://t.me/${u}`],
    ["X (Twitter)", "social", (u) => `https://x.com/${u}`],
    ["Instagram", "social", (u) => `https://www.instagram.com/${u}/`],
    ["TikTok", "social", (u) => `https://www.tiktok.com/@${u}`],
    ["VK", "social", (u) => `https://vk.com/${u}`],
    ["YouTube", "media", (u) => `https://www.youtube.com/@${u}`],
    ["Twitch", "media", (u) => `https://www.twitch.tv/${u}`],
    ["LinkedIn", "social", (u) => `https://www.linkedin.com/in/${u}`],
    ["Reddit", "forum", (u) => `https://www.reddit.com/user/${u}`],
    ["Habr", "forum", (u) => `https://habr.com/ru/users/${u}/`],
    ["Medium", "social", (u) => `https://medium.com/@${u}`],
    ["Dev.to", "coding", (u) => `https://dev.to/${u}`],
    ["PyPI", "coding", (u) => `https://pypi.org/user/${u}/`],
    ["Docker Hub", "coding", (u) => `https://hub.docker.com/u/${u}`],
    ["Keybase", "identity", (u) => `https://keybase.io/${u}`],
    ["Steam", "media", (u) => `https://steamcommunity.com/id/${u}`],
    ["Pinterest", "social", (u) => `https://www.pinterest.com/${u}/`],
    ["Dribbble", "social", (u) => `https://dribbble.com/${u}`],
    ["Behance", "social", (u) => `https://www.behance.net/${u}`],
    ["SoundCloud", "media", (u) => `https://soundcloud.com/${u}`],
  ];

  function cleanText(text, maxLen = 220) {
    if (!text) return null;
    const cleaned = String(text).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    if (!cleaned) return null;
    return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen)}…` : cleaned;
  }

  async function fetchJson(url, timeoutMs = 7000) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: "application/json" } });
      if (!res.ok) return null;
      return await res.json();
    } catch (_) {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async function sha256Hex(str) {
    const bytes = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function probeImage(url, timeoutMs = 5000) {
    return new Promise((resolve) => {
      const img = new Image();
      const timer = setTimeout(() => resolve(false), timeoutMs);
      img.onload = () => { clearTimeout(timer); resolve(true); };
      img.onerror = () => { clearTimeout(timer); resolve(false); };
      img.src = url;
    });
  }

  async function dohQuery(name, type) {
    const data = await fetchJson(
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`
    );
    if (!data || !Array.isArray(data.Answer)) return [];
    return data.Answer.map((a) => String(a.data || "").replace(/^"|"$/g, "").trim()).filter(Boolean);
  }

  // --- Browser Providers ---

  async function runBrowserDirectAPIs(u) {
    const enc = encodeURIComponent(u);
    const checks = [
      // GitHub
      async () => {
        const d = await fetchJson(`https://api.github.com/users/${enc}`);
        if (!d || !d.login) return null;
        const meta = {};
        if (d.name) meta.display_name = d.name;
        if (d.bio) meta.bio = cleanText(d.bio);
        if (d.location) meta.location = d.location;
        if (d.company) meta.company = d.company;
        if (d.blog) meta.website = d.blog;
        if (d.avatar_url) meta.avatar = d.avatar_url;
        if (d.followers != null) meta.followers = d.followers;
        if (d.public_repos != null) meta.public_repos = d.public_repos;
        if (d.twitter_username) meta.twitter = d.twitter_username;
        const parts = [d.name, d.location, `${d.public_repos || 0} repos · ${d.followers || 0} followers`].filter(Boolean);
        return {
          site: "GitHub",
          url: d.html_url || `https://github.com/${u}`,
          category: "coding",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.98,
          metadata: meta,
          snippet: parts.join(" · "),
        };
      },
      // GitLab
      async () => {
        const list = await fetchJson(`https://gitlab.com/api/v4/users?username=${enc}`);
        if (!Array.isArray(list) || !list.length) return null;
        const d = list[0];
        return {
          site: "GitLab",
          url: d.web_url || `https://gitlab.com/${u}`,
          category: "coding",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.96,
          metadata: { display_name: d.name, avatar: d.avatar_url, state: d.state },
          snippet: d.name || `@${u}`,
        };
      },
      // Codeberg (Gitea)
      async () => {
        const d = await fetchJson(`https://codeberg.org/api/v1/users/${enc}`);
        if (!d || !d.login) return null;
        return {
          site: "Codeberg",
          url: `https://codeberg.org/${d.login}`,
          category: "coding",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.95,
          metadata: {
            display_name: d.full_name || undefined,
            location: d.location || undefined,
            bio: cleanText(d.description) || undefined,
            avatar: d.avatar_url || undefined,
          },
          snippet: [d.full_name, d.location, cleanText(d.description, 100)].filter(Boolean).join(" · ") || `@${d.login}`,
        };
      },
      // Bluesky
      async () => {
        const handle = u.includes(".") ? u : `${u}.bsky.social`;
        const d = await fetchJson(
          `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(handle)}`
        );
        if (!d || !d.handle) return null;
        return {
          site: "Bluesky",
          url: `https://bsky.app/profile/${d.handle}`,
          category: "social",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.96,
          metadata: {
            display_name: d.displayName || undefined,
            bio: cleanText(d.description) || undefined,
            avatar: d.avatar || undefined,
            followers: d.followersCount,
          },
          snippet: `${d.displayName || d.handle} · ${d.followersCount || 0} followers`,
        };
      },
      // Mastodon
      async () => {
        const d = await fetchJson(`https://mastodon.social/api/v1/accounts/lookup?acct=${enc}`);
        if (!d || !d.url) return null;
        return {
          site: "Mastodon (mastodon.social)",
          url: d.url,
          category: "social",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.95,
          metadata: {
            display_name: d.display_name || undefined,
            bio: cleanText(d.note) || undefined,
            avatar: d.avatar || undefined,
            followers: d.followers_count,
          },
          snippet: `${d.display_name || u} · ${d.followers_count || 0} followers`,
        };
      },
      // Hacker News
      async () => {
        const d = await fetchJson(`https://hacker-news.firebaseio.com/v0/user/${enc}.json`);
        if (!d || !d.id) return null;
        const about = cleanText(d.about);
        return {
          site: "Hacker News",
          url: `https://news.ycombinator.com/user?id=${d.id}`,
          category: "forum",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.96,
          metadata: { karma: d.karma, bio: about || undefined },
          snippet: `karma: ${d.karma || 0}${about ? ` · ${about.slice(0, 100)}` : ""}`,
        };
      },
      // Wikipedia EN
      async () => {
        const d = await fetchJson(
          `https://en.wikipedia.org/w/api.php?origin=*&action=query&list=users&ususers=${enc}&usprop=registration|editcount&format=json`
        );
        const usr = d && d.query && d.query.users && d.query.users[0];
        if (!usr || usr.missing !== undefined || usr.invalid !== undefined) return null;
        return {
          site: "Wikipedia (EN)",
          url: `https://en.wikipedia.org/wiki/User:${encodeURIComponent(usr.name || u)}`,
          category: "forum",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.93,
          metadata: { editcount: usr.editcount, created_at: usr.registration },
          snippet: `${usr.editcount || 0} правок · регистрация: ${(usr.registration || "—").slice(0, 10)}`,
        };
      },
      // Wikipedia RU
      async () => {
        const d = await fetchJson(
          `https://ru.wikipedia.org/w/api.php?origin=*&action=query&list=users&ususers=${enc}&usprop=registration|editcount&format=json`
        );
        const usr = d && d.query && d.query.users && d.query.users[0];
        if (!usr || usr.missing !== undefined || usr.invalid !== undefined) return null;
        return {
          site: "Wikipedia (RU)",
          url: `https://ru.wikipedia.org/wiki/Участник:${encodeURIComponent(usr.name || u)}`,
          category: "forum",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.93,
          metadata: { editcount: usr.editcount, created_at: usr.registration },
          snippet: `${usr.editcount || 0} правок · регистрация: ${(usr.registration || "—").slice(0, 10)}`,
        };
      },
      // npm
      async () => {
        const d = await fetchJson(`https://registry.npmjs.org/-/v1/search?text=maintainer:${enc}&size=3`);
        if (!d || !d.total) return null;
        const pkgs = (d.objects || []).map((o) => o.package && o.package.name).filter(Boolean);
        return {
          site: "npm",
          url: `https://www.npmjs.com/~${u}`,
          category: "coding",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.95,
          metadata: { packages_count: d.total, sample_packages: pkgs },
          snippet: `${d.total} пакетов: ${pkgs.slice(0, 3).join(", ")}`,
        };
      },
      // Codeforces
      async () => {
        const d = await fetchJson(`https://codeforces.com/api/user.info?handles=${enc}`);
        if (!d || d.status !== "OK" || !d.result || !d.result.length) return null;
        const usr = d.result[0];
        const name = [usr.firstName, usr.lastName].filter(Boolean).join(" ") || undefined;
        const loc = [usr.city, usr.country].filter(Boolean).join(", ") || undefined;
        return {
          site: "Codeforces",
          url: `https://codeforces.com/profile/${usr.handle}`,
          category: "coding",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.95,
          metadata: {
            display_name: name,
            location: loc,
            rating: usr.rating,
            rank: usr.rank,
            avatar: usr.titlePhoto,
          },
          snippet: [name, loc, usr.rank ? `${usr.rank} (${usr.rating})` : null].filter(Boolean).join(" · ") || usr.handle,
        };
      },
      // Lichess
      async () => {
        const d = await fetchJson(`https://lichess.org/api/user/${enc}`);
        if (!d || !d.id || d.disabled) return null;
        const prof = d.profile || {};
        const name = [prof.firstName, prof.lastName].filter(Boolean).join(" ") || undefined;
        return {
          site: "Lichess",
          url: d.url || `https://lichess.org/@/${d.username}`,
          category: "media",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.94,
          metadata: {
            display_name: name,
            location: prof.location || prof.country || undefined,
            bio: cleanText(prof.bio) || undefined,
          },
          snippet: [name, prof.location, d.count && d.count.all ? `${d.count.all} партий` : null].filter(Boolean).join(" · ") || d.username,
        };
      },
      // Chess.com
      async () => {
        const d = await fetchJson(`https://api.chess.com/pub/player/${enc.toLowerCase()}`);
        if (!d || !d.username) return null;
        return {
          site: "Chess.com",
          url: d.url || `https://www.chess.com/member/${d.username}`,
          category: "media",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.95,
          metadata: {
            display_name: d.name || undefined,
            location: d.location || undefined,
            avatar: d.avatar || undefined,
            followers: d.followers,
          },
          snippet: [d.name, d.location, d.followers ? `${d.followers} followers` : null].filter(Boolean).join(" · ") || d.username,
        };
      },
      // StackOverflow
      async () => {
        const d = await fetchJson(
          `https://api.stackexchange.com/2.3/users?inname=${enc}&site=stackoverflow&pagesize=3&order=desc&sort=reputation`
        );
        const exact = (d && d.items || []).find(
          (i) => (i.display_name || "").toLowerCase() === u.toLowerCase()
        );
        if (!exact) return null;
        return {
          site: "Stack Overflow",
          url: exact.link,
          category: "coding",
          status: "found",
          sources: ["browser-apis"],
          confidence: 0.92,
          metadata: {
            display_name: exact.display_name,
            location: exact.location || undefined,
            reputation: exact.reputation,
            avatar: exact.profile_image,
          },
          snippet: `${exact.display_name} · rep: ${exact.reputation}${exact.location ? ` · ${exact.location}` : ""}`,
        };
      },
    ];

    const settled = await Promise.all(checks.map((fn) => fn().catch(() => null)));
    return settled.filter(Boolean);
  }

  async function runBrowserQuickLinks(u) {
    return CURATED_QUICK_LINKS.map(([site, category, urlFn]) => ({
      site: `${site} (прямая ссылка)`,
      url: urlFn(encodeURIComponent(u)),
      category,
      status: "possible",
      sources: ["quick-links"],
      confidence: 0.55,
      metadata: { note: "Прямой переход (проверка HTTP-статуса в браузере ограничена политикой CORS; для автопроверки 400+ / 11K+ сайтов запустите GitHub Actions или Backend)" },
      snippet: "Открыть профиль вручную для визуальной проверки",
    }));
  }

  async function runBrowserEmailOSINT(email) {
    const clean = email.trim().toLowerCase();
    const [, domain] = clean.split("@");
    if (!domain) return [];

    const [mxRaw, txtRaw, dmarcRaw, sha256, ghData] = await Promise.all([
      dohQuery(domain, "MX"),
      dohQuery(domain, "TXT"),
      dohQuery(`_dmarc.${domain}`, "TXT"),
      sha256Hex(clean),
      fetchJson(`https://api.github.com/search/users?q=${encodeURIComponent(`${clean} in:email`)}&per_page=3`),
    ]);

    const mxHosts = mxRaw.map((m) => m.split(/\s+/).pop().replace(/\.$/, "").toLowerCase());
    const spf = txtRaw.find((t) => t.toLowerCase().startsWith("v=spf1")) || null;
    const dmarc = dmarcRaw.find((t) => t.toLowerCase().startsWith("v=dmarc1")) || null;

    let provider = "Собственный / неизвестный почтовый сервер";
    for (const mx of mxHosts) {
      for (const [suffix, label] of Object.entries(PROVIDER_HINTS)) {
        if (mx.endsWith(suffix)) { provider = label; break; }
      }
      if (provider !== "Собственный / неизвестный почтовый сервер") break;
    }

    const disposable = DISPOSABLE_DOMAINS.has(domain);
    const findings = [
      {
        site: `Email DNS & MX (${domain})`,
        url: null,
        category: "email",
        status: "info",
        sources: ["browser-email"],
        confidence: 1.0,
        metadata: { domain, mx_records: mxHosts, has_mx: mxHosts.length > 0, mail_provider: provider, spf, dmarc, disposable },
        snippet:
          (mxHosts.length
            ? `Провайдер: ${provider} · MX: ${mxHosts.slice(0, 3).join(", ")}`
            : "MX-записи не найдены (домен не принимает почту)") +
          (disposable ? " · Временный (disposable) домен" : ""),
      },
    ];

    // Gravatar SHA-256 avatar probe (works directly in browser without CORS!)
    const gravatarUrl = `https://www.gravatar.com/avatar/${sha256}?d=404&s=200`;
    const hasGravatar = await probeImage(gravatarUrl);
    if (hasGravatar) {
      findings.push({
        site: "Gravatar",
        url: `https://gravatar.com/${sha256}`,
        category: "identity",
        status: "found",
        sources: ["browser-email"],
        confidence: 0.96,
        metadata: { avatar: gravatarUrl, sha256 },
        snippet: "Найден опубликованный профиль/аватар Gravatar для этого email",
      });
    }

    // GitHub public email lookup
    if (ghData && Array.isArray(ghData.items) && ghData.items.length) {
      const u = ghData.items[0];
      findings.push({
        site: "GitHub (by Email)",
        url: u.html_url,
        category: "coding",
        status: "found",
        sources: ["browser-email"],
        confidence: 0.97,
        metadata: { username: u.login, avatar: u.avatar_url },
        snippet: `Аккаунт @${u.login} найден по публичному email на GitHub`,
      });
    }

    // OpenPGP keyserver link
    findings.push({
      site: "OpenPGP Keyserver",
      url: `https://keys.openpgp.org/search?q=${encodeURIComponent(clean)}`,
      category: "identity",
      status: "info",
      sources: ["browser-email"],
      confidence: 0.7,
      metadata: { email: clean },
      snippet: "Проверить опубликованный публичный PGP-ключ на keys.openpgp.org",
    });

    return findings;
  }

  async function runBrowserPhoneOSINT(rawPhone) {
    const cleaned = rawPhone.replace(/[^\d+]/g, "");
    const digits = cleaned.replace(/^\+/, "");
    const e164 = `+${digits}`;

    let country = "Не определена (укажите код страны, напр. +1 / +7 / +44)";
    let code = "";
    let tz = "";
    for (const [cc, label, zone] of COUNTRY_CODES) {
      if (digits.startsWith(cc)) {
        code = `+${cc}`;
        country = label;
        tz = zone;
        break;
      }
    }

    const validLen = digits.length >= 7 && digits.length <= 15;
    const dork = `"${e164}" OR "${digits}"`;

    return [
      {
        site: `Phone Metadata (${e164})`,
        url: null,
        category: "phone",
        status: validLen ? "found" : "info",
        sources: ["browser-phone"],
        confidence: validLen && code ? 0.95 : 0.65,
        metadata: {
          e164,
          country_code: code || "?",
          location: country,
          timezones: tz ? [tz] : [],
          digits_length: digits.length,
          valid_length: validLen,
        },
        snippet: `${validLen ? "Корректная длина" : "Нестандартная длина"} (${digits.length} цифр) · ${country}${tz ? ` · TZ: ${tz}` : ""}`,
      },
      {
        site: "Google Public Mentions (Dork)",
        url: `https://www.google.com/search?q=${encodeURIComponent(dork)}`,
        category: "phone",
        status: "info",
        sources: ["browser-phone"],
        confidence: 0.72,
        metadata: { query: dork },
        snippet: `Поиск публичных упоминаний по форматам: ${e164} / ${digits}`,
      },
      {
        site: "DuckDuckGo Public Mentions",
        url: `https://duckduckgo.com/?q=${encodeURIComponent(dork)}`,
        category: "phone",
        status: "info",
        sources: ["browser-phone"],
        confidence: 0.72,
        metadata: { query: dork },
        snippet: "Альтернативный поисковый запрос по открытым источникам",
      },
    ];
  }

  async function runBrowserDomainOSINT(domain) {
    const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    const [aRec, aaaaRec, mxRec, nsRec, txtRec, rdap, crt] = await Promise.all([
      dohQuery(clean, "A"),
      dohQuery(clean, "AAAA"),
      dohQuery(clean, "MX"),
      dohQuery(clean, "NS"),
      dohQuery(clean, "TXT"),
      fetchJson(`https://rdap.org/domain/${encodeURIComponent(clean)}`),
      fetchJson(`https://crt.sh/?q=${encodeURIComponent(clean)}&output=json`, 9000),
    ]);

    const findings = [];
    if (aRec.length || aaaaRec.length || mxRec.length || nsRec.length) {
      const parts = [];
      if (aRec.length) parts.push(`A: ${aRec.slice(0, 2).join(", ")}`);
      if (mxRec.length) parts.push(`MX: ${mxRec.length}`);
      if (nsRec.length) parts.push(`NS: ${nsRec.slice(0, 2).join(", ")}`);
      findings.push({
        site: `DNS Records (${clean})`,
        url: `https://${clean}`,
        category: "dns",
        status: "found",
        sources: ["browser-domain"],
        confidence: 1.0,
        metadata: { A: aRec, AAAA: aaaaRec, MX: mxRec, NS: nsRec, TXT: txtRec.slice(0, 8) },
        snippet: parts.join(" · "),
      });
    }

    if (rdap && rdap.ldhName) {
      const events = {};
      for (const ev of rdap.events || []) events[ev.eventAction] = ev.eventDate;
      let registrar = null;
      for (const ent of rdap.entities || []) {
        if ((ent.roles || []).includes("registrar")) {
          const vcard = (ent.vcardArray && ent.vcardArray[1]) || [];
          const fn = vcard.find((x) => Array.isArray(x) && x[0] === "fn");
          if (fn && fn[3]) registrar = fn[3];
        }
      }
      const parts = [];
      if (registrar) parts.push(`Регистратор: ${registrar}`);
      if (events.registration) parts.push(`Создан: ${String(events.registration).slice(0, 10)}`);
      if (events.expiration) parts.push(`Истекает: ${String(events.expiration).slice(0, 10)}`);
      findings.push({
        site: "RDAP / WHOIS",
        url: `https://rdap.org/domain/${clean}`,
        category: "dns",
        status: "info",
        sources: ["browser-domain"],
        confidence: 0.98,
        metadata: {
          registrar,
          registered: events.registration,
          expires: events.expiration,
          status: rdap.status,
          nameservers: (rdap.nameservers || []).map((n) => n.ldhName).filter(Boolean),
        },
        snippet: parts.join(" · ") || "Данные RDAP получены",
      });
    }

    if (Array.isArray(crt) && crt.length) {
      const names = new Set();
      for (const entry of crt.slice(0, 80)) {
        for (const n of String(entry.name_value || "").split("\n")) {
          const trimmed = n.trim().toLowerCase();
          if (trimmed && !trimmed.startsWith("*")) names.add(trimmed);
        }
      }
      const sample = Array.from(names).slice(0, 20);
      findings.push({
        site: "Certificate Transparency (crt.sh)",
        url: `https://crt.sh/?q=${encodeURIComponent(clean)}`,
        category: "dns",
        status: "info",
        sources: ["browser-domain"],
        confidence: 0.94,
        metadata: { certificates_checked: crt.length, unique_subdomains: sample },
        snippet: `Сертификатов: ${crt.length} · Поддомены: ${sample.slice(0, 4).join(", ") || clean}`,
      });
    }

    return findings;
  }

  function mergeFindings(allFindings) {
    const map = new Map();
    for (const item of allFindings) {
      let key;
      if (item.url) {
        try {
          const u = new URL(item.url);
          key = `url:${u.hostname.replace(/^www\./, "").toLowerCase()}${u.pathname.replace(/\/$/, "").toLowerCase()}${u.search.toLowerCase()}`;
        } catch (_) {
          key = `url:${item.url.toLowerCase()}`;
        }
      } else {
        key = `site:${item.site.toLowerCase()}:${item.category}`;
      }
      if (!map.has(key)) {
        map.set(key, { ...item, sources: [...(item.sources || [])], metadata: { ...(item.metadata || {}) } });
      } else {
        const ex = map.get(key);
        for (const s of item.sources || []) {
          if (!ex.sources.includes(s)) ex.sources.push(s);
        }
        if ((!ex.snippet && item.snippet) || (item.snippet && ex.snippet && item.snippet.length > ex.snippet.length)) {
          ex.snippet = item.snippet;
        }
        Object.assign(ex.metadata, item.metadata || {});
        ex.confidence = Math.min(0.99, Math.max(ex.confidence, item.confidence) + 0.05 * (ex.sources.length - 1));
      }
    }
    const merged = Array.from(map.values());
    merged.sort((a, b) => (b.status === "found" ? 1 : 0) - (a.status === "found" ? 1 : 0) || b.confidence - a.confidence || a.site.localeCompare(b.site));
    return merged;
  }

  function buildSummary(findings) {
    const s = { display_names: [], avatars: [], locations: [], bios: [], websites: [], emails_found: [], extra: {} };
    const add = (arr, v, max = 5) => {
      if (v && typeof v === "string" && !arr.includes(v.trim()) && arr.length < max) arr.push(v.trim());
    };
    for (const f of findings) {
      const m = f.metadata || {};
      add(s.display_names, m.display_name);
      add(s.avatars, m.avatar, 3);
      add(s.locations, m.location);
      add(s.bios, m.bio, 3);
      add(s.websites, m.website);
      if (f.category === "phone" && m.e164) {
        s.extra.phone = { e164: m.e164, location: m.location, carrier: "—", line_type: `${m.digits_length} цифр` };
      }
      if (f.category === "email" && m.mail_provider) {
        s.extra.mail_provider = m.mail_provider;
      }
      if (f.site === "RDAP / WHOIS" && m.registrar) {
        s.extra.registrar = m.registrar;
      }
    }
    return s;
  }

  const BROWSER_ENGINES = [
    {
      id: "browser-apis",
      name: "Browser Public APIs (13+)",
      description: "Прямые CORS-запросы из браузера: GitHub, GitLab, Codeberg, Bluesky, Mastodon, Hacker News, Wikipedia EN/RU, npm, Codeforces, Lichess, Chess.com, Stack Overflow.",
      supported_types: ["username"],
      available: true,
      mode: "public-http",
      default_enabled: true,
    },
    {
      id: "quick-links",
      name: "Sherlock/Maigret Quick Links",
      description: "20 прямых ссылок на популярные соцсети и площадки (Telegram, X, Instagram, VK, TikTok, YouTube, Habr и др.) для мгновенной ручной проверки.",
      supported_types: ["username"],
      available: true,
      mode: "passive",
      default_enabled: true,
    },
    {
      id: "browser-email",
      name: "Email DoH & Gravatar",
      description: "DNS-over-HTTPS (MX/SPF/DMARC), почтовый провайдер, Gravatar (SHA-256), GitHub Email Search и OpenPGP.",
      supported_types: ["email"],
      available: true,
      mode: "passive",
      default_enabled: true,
    },
    {
      id: "browser-phone",
      name: "Phone Prefix & Dorks",
      description: "Определение страны и часового пояса по международному коду, нормализация E.164 и поисковые дорки.",
      supported_types: ["phone"],
      available: true,
      mode: "passive",
      default_enabled: true,
    },
    {
      id: "browser-domain",
      name: "Domain DoH, RDAP & crt.sh",
      description: "DNS-over-HTTPS (A/AAAA/MX/NS/TXT), регистрация RDAP/WHOIS и история SSL-сертификатов crt.sh.",
      supported_types: ["domain"],
      available: true,
      mode: "passive",
      default_enabled: true,
    },
    {
      id: "sherlock",
      name: "Sherlock (400+ сайтов)",
      description: "Требует Python-бэкенд (Codespaces, Docker, локальный запуск или GitHub Actions).",
      supported_types: ["username"],
      available: false,
      availability_note: "Недоступен в статическом режиме GitHub Pages — запустите через Actions или подключите Backend URL.",
      mode: "public-http",
      default_enabled: false,
    },
    {
      id: "maigret",
      name: "Maigret (11 000+ сайтов)",
      description: "Требует Python-бэкенд (Codespaces, Docker, локальный запуск или GitHub Actions).",
      supported_types: ["username"],
      available: false,
      availability_note: "Недоступен в статическом режиме GitHub Pages — запустите через Actions или подключите Backend URL.",
      mode: "public-http",
      default_enabled: false,
    },
  ];

  async function runBrowserSearch(query, detectedType, selectedIds, callbacks) {
    const t0 = performance.now();
    const id = Math.random().toString(16).slice(2, 14);
    const plan = [];

    const wants = (engId) => !selectedIds || !selectedIds.size || selectedIds.has(engId);

    if (detectedType === "username") {
      if (wants("browser-apis")) plan.push({ id: "browser-apis", name: "Browser Public APIs (13+)", fn: () => runBrowserDirectAPIs(query) });
      if (wants("quick-links")) plan.push({ id: "quick-links", name: "Sherlock/Maigret Quick Links", fn: () => runBrowserQuickLinks(query) });
    } else if (detectedType === "email") {
      if (wants("browser-email")) plan.push({ id: "browser-email", name: "Email DoH & Gravatar", fn: () => runBrowserEmailOSINT(query) });
      const [localPart, domainPart] = query.toLowerCase().split("@");
      if (localPart && localPart.length >= 3 && !["info", "admin", "support", "hello", "contact"].includes(localPart)) {
        if (wants("browser-apis")) plan.push({ id: "browser-apis", name: "Browser Public APIs (13+)", fn: () => runBrowserDirectAPIs(localPart) });
      }
      if (domainPart && !PUBLIC_MAIL_DOMAINS.has(domainPart)) {
        if (wants("browser-domain")) plan.push({ id: "browser-domain", name: "Domain DoH, RDAP & crt.sh", fn: () => runBrowserDomainOSINT(domainPart) });
      }
    } else if (detectedType === "phone") {
      plan.push({ id: "browser-phone", name: "Phone Prefix & Dorks", fn: () => runBrowserPhoneOSINT(query) });
    } else if (detectedType === "domain") {
      plan.push({ id: "browser-domain", name: "Domain DoH, RDAP & crt.sh", fn: () => runBrowserDomainOSINT(query) });
    }

    const engineStates = plan.map((p) => ({
      engine_id: p.id,
      engine_name: p.name,
      status: "running",
      findings_count: 0,
      elapsed_ms: 0,
      message: `Поиск «${query}»`,
    }));

    callbacks.onStarted({ id, query, detected_type: detectedType, depth: "fast", engines: engineStates });

    const allRaw = [];
    let completed = 0;

    await Promise.all(
      plan.map(async (step, idx) => {
        const st = performance.now();
        try {
          const hits = await step.fn();
          const elapsed = Math.round(performance.now() - st);
          engineStates[idx] = {
            engine_id: step.id,
            engine_name: step.name,
            status: "completed",
            findings_count: hits.length,
            elapsed_ms: elapsed,
            message: `Найдено: ${hits.length}`,
          };
          allRaw.push(...hits);
        } catch (err) {
          const elapsed = Math.round(performance.now() - st);
          engineStates[idx] = {
            engine_id: step.id,
            engine_name: step.name,
            status: "error",
            findings_count: 0,
            elapsed_ms: elapsed,
            message: String(err),
          };
        }
        completed += 1;
        const merged = mergeFindings(allRaw);
        const summary = buildSummary(merged);
        callbacks.onUpdate({
          engine: engineStates[idx],
          completed,
          total: plan.length,
          findings: merged,
          summary,
          total_unique: merged.length,
          multi_source_confirmed: merged.filter((f) => (f.sources || []).length > 1).length,
        });
      })
    );

    const finalFindings = mergeFindings(allRaw);
    const report = {
      id,
      query,
      detected_type: detectedType,
      depth: "fast",
      created_at: new Date().toISOString(),
      elapsed_ms: Math.round(performance.now() - t0),
      engines: engineStates,
      summary: buildSummary(finalFindings),
      findings: finalFindings,
      total_unique: finalFindings.length,
      multi_source_confirmed: finalFindings.filter((f) => (f.sources || []).length > 1).length,
    };
    callbacks.onCompleted(report);
    return report;
  }

  function exportReportClient(report, fmt) {
    const safe = report.query.replace(/[^a-zA-Z0-9._-]/g, "_");
    let content = "";
    let mime = "application/json;charset=utf-8";
    let ext = "json";

    if (fmt === "csv") {
      mime = "text/csv;charset=utf-8";
      ext = "csv";
      const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
      const rows = [["Site", "Category", "URL", "Confidence", "Sources", "Snippet"].join(",")];
      for (const f of report.findings || []) {
        rows.push([
          esc(f.site), esc(f.category), esc(f.url || ""),
          esc(`${Math.round((f.confidence || 0) * 100)}%`),
          esc((f.sources || []).join(", ")), esc(f.snippet || ""),
        ].join(","));
      }
      content = rows.join("\n");
    } else if (fmt === "md") {
      mime = "text/markdown;charset=utf-8";
      ext = "md";
      const lines = [
        `# OSINT-отчёт Sherlock Hub: \`${report.query}\``,
        "",
        `- **Тип:** \`${report.detected_type}\``,
        `- **Дата (UTC):** ${report.created_at}`,
        `- **Уникальных находок:** ${report.total_unique}`,
        "",
        "| Платформа | Категория | Уверенность | Источники | Ссылка / Детали |",
        "| :--- | :--- | ---: | :--- | :--- |",
      ];
      for (const f of report.findings || []) {
        const link = f.url ? `[${f.url}](${f.url})` : (f.snippet || "—");
        lines.push(`| ${f.site} | ${f.category} | ${Math.round((f.confidence || 0) * 100)}% | ${(f.sources || []).join(", ")} | ${link} |`);
      }
      content = lines.join("\n");
    } else {
      content = JSON.stringify(report, null, 2);
    }

    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sherlock-hub-${safe}.${ext}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  window.SherlockBrowserOSINT = {
    ENGINES: BROWSER_ENGINES,
    runBrowserSearch,
    exportReportClient,
  };
})();
