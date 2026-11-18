(() => {
  const SAVE_KEY = 'paws_runes_save_v1';
  const CAT_MODE_KEY = 'paws_runes_cat_video_mode';

  // --- Менеджер локальных видео-котиков (/cats/manifest.json) ---
  const VideoCatManager = {
    urls: [],
    loaded: false,
    enabled: localStorage.getItem(CAT_MODE_KEY) === '1',

    async init(onReady) {
      try {
        const resp = await fetch('/cats/manifest.json', { cache: 'no-store' });
        if (resp.ok) {
          const arr = await resp.json();
          if (Array.isArray(arr)) this.urls = arr;
        }
      } catch (_) {
        this.urls = [];
      }
      this.loaded = true;
      if (onReady) onReady();
    },

    getMediaHtml(seedIndex, floorNum, fallbackSvg) {
      if (!this.enabled || this.urls.length === 0) {
        return fallbackSvg;
      }
      const rawUrl = this.urls[Math.abs(seedIndex) % this.urls.length];
      const src = `${rawUrl}?f=${floorNum}`;
      const lower = rawUrl.toLowerCase();
      if (lower.endsWith('.mp4') || lower.endsWith('.webm')) {
        return `<video src="${src}" autoplay loop muted playsinline preload="metadata"></video>`;
      }
      return `<img src="${src}" alt="Котик" loading="lazy" />`;
    },
  };

  // --- SVG-генератор для персонажей и карт (когда видеорежим выключен) ---
  function makeSvgArt(kind, accent = '#38bdf8') {
    const arts = {
      hero: `<svg viewBox="0 0 120 90"><rect width="120" height="90" fill="#091124"/><circle cx="60" cy="48" r="26" fill="#1e293b" stroke="${accent}" stroke-width="2.5"/><polygon points="38,34 45,14 55,28" fill="#1e293b" stroke="${accent}" stroke-width="2"/><polygon points="82,34 75,14 65,28" fill="#1e293b" stroke="${accent}" stroke-width="2"/><circle cx="51" cy="45" r="4" fill="#38bdf8"/><circle cx="69" cy="45" r="4" fill="#38bdf8"/><path d="M54,56 Q60,61 66,56" stroke="#f8fafc" stroke-width="2" fill="none"/><path d="M22,74 L42,54" stroke="#fbbf24" stroke-width="4" stroke-linecap="round"/></svg>`,
      slime: `<svg viewBox="0 0 120 90"><rect width="120" height="90" fill="#0d1726"/><path d="M28,68 Q28,28 60,28 Q92,28 92,68 Z" fill="#10b981" opacity="0.85"/><circle cx="48" cy="50" r="4.5" fill="#06281e"/><circle cx="72" cy="50" r="4.5" fill="#06281e"/><path d="M50,60 Q60,65 70,60" stroke="#06281e" stroke-width="2.5" fill="none"/></svg>`,
      vacuum: `<svg viewBox="0 0 120 90"><rect width="120" height="90" fill="#130f26"/><ellipse cx="60" cy="54" rx="34" ry="18" fill="#334155" stroke="#fb7185" stroke-width="2.5"/><circle cx="60" cy="48" r="10" fill="#0f172a" stroke="#fb7185" stroke-width="2"/><circle cx="60" cy="48" r="4" fill="#ef4444"/><path d="M26,54 L14,48 M94,54 L106,48" stroke="#94a3b8" stroke-width="3"/></svg>`,
      hound: `<svg viewBox="0 0 120 90"><rect width="120" height="90" fill="#1a0e1a"/><polygon points="36,24 44,40 30,44" fill="#7f1d1d"/><polygon points="84,24 76,40 90,44" fill="#7f1d1d"/><circle cx="60" cy="48" r="24" fill="#450a0a" stroke="#fb7185" stroke-width="2.5"/><circle cx="51" cy="44" r="4" fill="#fbbf24"/><circle cx="69" cy="44" r="4" fill="#fbbf24"/><path d="M48,58 L54,53 L60,58 L66,53 L72,58" stroke="#f8fafc" stroke-width="2" fill="none"/></svg>`,
      boss: `<svg viewBox="0 0 120 90"><rect width="120" height="90" fill="#1b102c"/><polygon points="35,28 45,8 56,22 64,22 75,8 85,28" fill="#fbbf24" stroke="#f59e0b" stroke-width="1.5"/><circle cx="60" cy="52" r="26" fill="#312e81" stroke="#fbbf24" stroke-width="2.5"/><circle cx="50" cy="48" r="4.5" fill="#fb7185"/><circle cx="70" cy="48" r="4.5" fill="#fb7185"/><path d="M48,62 Q60,56 72,62" stroke="#fbbf24" stroke-width="2.5" fill="none"/></svg>`,
      attack: `<svg viewBox="0 0 120 70"><rect width="120" height="70" fill="#170b18"/><path d="M30,52 L88,16" stroke="${accent}" stroke-width="5" stroke-linecap="round"/><path d="M48,56 L94,28" stroke="#fda4af" stroke-width="3" stroke-linecap="round"/><circle cx="88" cy="16" r="6" fill="#fff" opacity="0.7"/></svg>`,
      skill: `<svg viewBox="0 0 120 70"><rect width="120" height="70" fill="#08182b"/><path d="M60,12 L84,24 V42 C84,54 60,62 60,62 C60,62 36,54 36,42 V24 Z" fill="rgba(56,189,248,0.22)" stroke="${accent}" stroke-width="3"/><circle cx="60" cy="36" r="7" fill="${accent}"/></svg>`,
      power: `<svg viewBox="0 0 120 70"><rect width="120" height="70" fill="#1a1409"/><polygon points="60,10 72,32 96,35 78,51 82,66 60,56 38,66 42,51 24,35 48,32" fill="rgba(251,191,36,0.25)" stroke="${accent}" stroke-width="2.5"/></svg>`,
    };
    return arts[kind] || arts.skill;
  }

  // --- База карт (18 уникальных карт с улучшениями +) ---
  const CARD_DB = {
    strike:       { name: 'Царапок',       type: 'attack', cost: 1, dmg: 6,  upDmg: 9,  art: 'attack', desc: (u) => `Наносит ${u ? 9 : 6} урона.` },
    defend:       { name: 'Клубок',        type: 'skill',  cost: 1, blk: 5,  upBlk: 8,  art: 'skill',  desc: (u) => `Даёт ${u ? 8 : 5} защиты.` },
    twin_claw:    { name: 'Двойной удар',  type: 'attack', cost: 1, dmg: 4,  hits: 2, upDmg: 6, art: 'attack', desc: (u) => `Наносит ${u ? 6 : 4} урона дважды.` },
    pounce:       { name: 'Наскок',        type: 'attack', cost: 2, dmg: 12, vuln: 2, upDmg: 16, upVuln: 3, art: 'attack', desc: (u) => `${u ? 16 : 12} урона и ${u ? 3 : 2} Уязвимости.` },
    purr_shield:  { name: 'Мур-Щит',       type: 'skill',  cost: 1, blk: 7,  draw: 1, upBlk: 10, art: 'skill', desc: (u) => `${u ? 10 : 7} защиты. Добор 1 карты.` },
    catnip_focus: { name: 'Мятный фокус',  type: 'skill',  cost: 0, energy: 1, draw: 1, exhaust: true, art: 'power', desc: (u) => `+1 ⚡ энергии, добор 1 карты.${u ? '' : ' Сжигается.'}` },
    iron_fur:     { name: 'Железная шерсть', type: 'power', cost: 2, metallicize: 3, upMet: 5, exhaust: true, art: 'power', desc: (u) => `Талант: +${u ? 5 : 3} защиты в начале хода.` },
    fire_rune:    { name: 'Руна огня',     type: 'attack', cost: 2, dmg: 14, selfStr: 2, upDmg: 18, upStr: 3, art: 'attack', desc: (u) => `${u ? 18 : 14} урона и +${u ? 3 : 2} Силы.` },
    venom_bite:   { name: 'Ядовитый укус', type: 'attack', cost: 1, dmg: 4,  poison: 4, upDmg: 6, upPoison: 6, art: 'attack', desc: (u) => `${u ? 6 : 4} урона и ${u ? 6 : 4} Яда.` },
    weaken_hiss:  { name: 'Шипение',       type: 'skill',  cost: 1, blk: 4,  weak: 2, upBlk: 7, upWeak: 3, art: 'skill', desc: (u) => `${u ? 7 : 4} защиты и ${u ? 3 : 2} Слабости врагу.` },
    shield_bash:  { name: 'Удар щитом',    type: 'attack', cost: 1, upCost: 0, bodySlam: true, art: 'attack', desc: () => `Урон равен вашей текущей защите.` },
    berserk_rage: { name: 'Когти ярости',  type: 'power',  cost: 1, selfStr: 3, upStr: 4, exhaust: true, art: 'power', desc: (u) => `Талант: +${u ? 4 : 3} Силы на весь бой.` },
    healing_lick: { name: 'Целебная мята', type: 'skill',  cost: 1, heal: 6, upHeal: 9, exhaust: true, art: 'skill', desc: (u) => `Лечит ${u ? 9 : 6} ОЗ. Сжигается.` },
    flurry:       { name: 'Шквал лапок',   type: 'attack', cost: 0, dmg: 3, draw: 1, upDmg: 5, art: 'attack', desc: (u) => `${u ? 5 : 3} урона. Добор 1 карты.` },
    arcane_shield:{ name: 'Рунный барьер', type: 'skill',  cost: 2, blk: 16, upBlk: 22, art: 'skill', desc: (u) => `Даёт ${u ? 22 : 16} защиты.` },
    toxic_cloud:  { name: 'Облако спор',   type: 'skill',  cost: 1, poison: 6, upPoison: 9, exhaust: true, art: 'power', desc: (u) => `Накладывает ${u ? 9 : 6} Яда. Сжигается.` },
    finisher:     { name: 'Выпад рыси',    type: 'attack', cost: 2, dmg: 18, upDmg: 25, art: 'attack', desc: (u) => `Наносит ${u ? 25 : 18} урона.` },
    lucky_coin:   { name: 'Золотой коготь',type: 'attack', cost: 1, dmg: 7, bonusGold: 12, upDmg: 10, upGold: 18, art: 'attack', desc: (u) => `${u ? 10 : 7} урона. Если убьёт: +${u ? 18 : 12} золота.` },
  };

  const REWARD_POOL = Object.keys(CARD_DB).filter((k) => k !== 'strike' && k !== 'defend');

  // --- Реликвии ---
  const RELIC_DB = {
    yarn_ball:   { name: '🧶 Амулет клубка',   desc: '+4 защиты в начале каждого боя' },
    claw_stone:  { name: '🪨 Точилка когтей',  desc: '+1 Силы в начале каждого боя' },
    mana_core:   { name: '⚡ Малый реактор',   desc: '+1 маны на 1-м ходу боя' },
    cat_grace:   { name: '🪶 Кошачья грация',  desc: '+1 карта в руку на 1-м ходу' },
    vamp_fang:   { name: '🩸 Вампирский клык', desc: '+4 ОЗ после каждой победы' },
    lucky_bell:  { name: '🔔 Колокольчик',     desc: '+30% золота за победы' },
  };

  // --- Пул врагов ---
  function createEnemyForNode(nodeType, floor) {
    const scale = 1 + floor * 0.14;
    if (nodeType === 'boss') {
      return {
        name: 'Древний Сфинкс',
        maxHp: Math.round(115 * (1 + floor * 0.04)),
        hp: Math.round(115 * (1 + floor * 0.04)),
        block: 0, str: 0, vuln: 0, weak: 0, poison: 0,
        art: 'boss',
        seed: 9,
        pattern: [
          { type: 'attack', val: 14, label: '🗡 Атака 14' },
          { type: 'defend_buff', blk: 12, str: 2, label: '🛡 Блок 12 + Сила 2' },
          { type: 'multi_attack', val: 8, hits: 2, label: '🗡 Серия 8x2' },
        ],
        turnIdx: 0,
      };
    }
    if (nodeType === 'elite') {
      return {
        name: floor > 6 ? 'Мега-Пылесос MK-II' : 'Пёс-Берсерк',
        maxHp: Math.round(52 * scale),
        hp: Math.round(52 * scale),
        block: 0, str: 1, vuln: 0, weak: 0, poison: 0,
        art: floor > 6 ? 'vacuum' : 'hound',
        seed: floor + 3,
        pattern: [
          { type: 'attack', val: Math.round(10 * scale), label: `🗡 Атака ${Math.round(10 * scale)}` },
          { type: 'defend_buff', blk: 8, str: 2, label: '🛡 Блок 8 + Сила 2' },
          { type: 'attack', val: Math.round(13 * scale), label: `🗡 Атака ${Math.round(13 * scale)}` },
        ],
        turnIdx: 0,
      };
    }
    const pool = [
      { name: 'Неоновый Слизень', baseHp: 24, baseAtk: 6, art: 'slime', seed: 1 },
      { name: 'Дрон-Пылесос',     baseHp: 28, baseAtk: 7, art: 'vacuum', seed: 2 },
      { name: 'Сторожевой Пёс',   baseHp: 32, baseAtk: 8, art: 'hound', seed: 4 },
    ];
    const tpl = pool[(floor + Math.floor(Math.random() * pool.length)) % pool.length];
    const hp = Math.round(tpl.baseHp * scale);
    const atk = Math.round(tpl.baseAtk * (1 + floor * 0.08));
    return {
      name: tpl.name,
      maxHp: hp, hp, block: 0, str: 0, vuln: 0, weak: 0, poison: 0,
      art: tpl.art, seed: tpl.seed + floor,
      pattern: [
        { type: 'attack', val: atk, label: `🗡 Атака ${atk}` },
        { type: 'defend_atk', blk: 5, val: Math.max(4, atk - 2), label: `🛡 Блок 5 + 🗡 ${Math.max(4, atk - 2)}` },
      ],
      turnIdx: 0,
    };
  }

  // --- Состояние забега ---
  let run = null;
  let combat = null;

  function makeStarterDeck() {
    const d = [];
    for (let i = 0; i < 4; i++) d.push({ id: 'strike', up: false });
    for (let i = 0; i < 4; i++) d.push({ id: 'defend', up: false });
    d.push({ id: 'twin_claw', up: false });
    d.push({ id: 'purr_shield', up: false });
    return d;
  }

  function generateDungeonMap() {
    const floors = [];
    for (let f = 1; f <= 12; f++) {
      if (f === 1) {
        floors.push([{ id: '1-0', type: 'battle', label: '⚔️ Бой' }]);
      } else if (f === 12) {
        floors.push([{ id: '12-0', type: 'boss', label: '👑 Босс: Сфинкс' }]);
      } else if (f === 6 || f === 11) {
        floors.push([
          { id: `${f}-0`, type: 'camp', label: '🔥 Костёр' },
          { id: `${f}-1`, type: 'shop', label: '🛒 Лавка' },
        ]);
      } else {
        const types = f >= 4 ? ['battle', 'battle', 'elite', 'camp', 'shop'] : ['battle', 'battle', 'camp'];
        const pick = () => types[Math.floor(Math.random() * types.length)];
        const labels = { battle: '⚔️ Бой', elite: '💀 Элита', camp: '🔥 Костёр', shop: '🛒 Лавка' };
        const t1 = pick();
        let t2 = pick();
        if (t2 === t1 && types.length > 1) t2 = t1 === 'battle' ? 'camp' : 'battle';
        floors.push([
          { id: `${f}-0`, type: t1, label: labels[t1] },
          { id: `${f}-1`, type: t2, label: labels[t2] },
        ]);
      }
    }
    return floors;
  }

  function newRun() {
    run = {
      floor: 1,
      clearedFloor: 0,
      hp: 75,
      maxHp: 75,
      gold: 55,
      deck: makeStarterDeck(),
      relics: ['yarn_ball'],
      map: generateDungeonMap(),
      screen: 'map', // map | combat | reward | camp | shop | victory | gameover
      rewardChoices: [],
      rewardRelic: null,
      shopStock: null,
      visitedNodes: [],
    };
    combat = null;
    saveRun();
    renderAll();
  }

  function saveRun() {
    try {
      localStorage.setItem(SAVE_KEY, JSON.stringify({ run, combatScreen: run?.screen }));
    } catch (_) {}
  }

  function loadRun() {
    try {
      const raw = localStorage.getItem(SAVE_KEY);
      if (!raw) return false;
      const parsed = JSON.parse(raw);
      if (parsed && parsed.run && Array.isArray(parsed.run.map)) {
        run = parsed.run;
        if (run.screen === 'combat') run.screen = 'map';
        return true;
      }
    } catch (_) {}
    return false;
  }

  // --- DOM элементы ---
  const stageEl = document.getElementById('gameStage');
  const floorEl = document.getElementById('runFloorEl');
  const hpEl = document.getElementById('runHpEl');
  const goldEl = document.getElementById('runGoldEl');
  const relicsEl = document.getElementById('runRelicsEl');
  const deckBtn = document.getElementById('deckBtn');
  const newRunBtn = document.getElementById('newRunBtn');
  const catToggle = document.getElementById('catVideoToggle');
  const deckModal = document.getElementById('deckModal');
  const deckModalGrid = document.getElementById('deckModalGrid');
  const deckModalTitle = document.getElementById('deckModalTitle');
  const deckModalClose = document.getElementById('deckModalClose');

  catToggle.checked = VideoCatManager.enabled;
  catToggle.addEventListener('change', () => {
    VideoCatManager.enabled = catToggle.checked;
    localStorage.setItem(CAT_MODE_KEY, VideoCatManager.enabled ? '1' : '0');
    renderAll();
  });

  newRunBtn.addEventListener('click', () => {
    if (confirm('Начать новый забег в подземелье?')) newRun();
  });

  deckModalClose.addEventListener('click', () => deckModal.classList.remove('open'));
  deckBtn.addEventListener('click', () => openDeckModal('Ваша колода', null));

  function openDeckModal(title, onPickCallback) {
    deckModalTitle.textContent = title;
    deckModalGrid.innerHTML = '';
    run.deck.forEach((cardObj, idx) => {
      const el = createCardElement(cardObj, idx + 10, true);
      if (onPickCallback) {
        el.title = 'Нажмите, чтобы выбрать';
        el.addEventListener('click', () => {
          deckModal.classList.remove('open');
          onPickCallback(idx);
        });
      }
      deckModalGrid.appendChild(el);
    });
    deckModal.classList.add('open');
  }

  function createCardElement(cardObj, artSeed, alwaysEnabled = false) {
    const def = CARD_DB[cardObj.id];
    const up = Boolean(cardObj.up);
    const cost = up && def.upCost !== undefined ? def.upCost : def.cost;
    const div = document.createElement('div');
    const canPlay = alwaysEnabled || (combat && combat.energy >= cost && !combat.busy);
    div.className = `play-card ${def.type}${canPlay ? '' : ' disabled'}`;

    const accent = def.type === 'attack' ? '#fb7185' : def.type === 'skill' ? '#38bdf8' : '#fbbf24';
    const artHtml = VideoCatManager.getMediaHtml(artSeed, run.floor, makeSvgArt(def.art, accent));
    const typeLabel = def.type === 'attack' ? 'Атака' : def.type === 'skill' ? 'Навык' : 'Талант';

    div.innerHTML = `
      <div class="card-top">
        <div class="card-cost">${cost}</div>
        <div class="card-name ${up ? 'upgraded' : ''}">${def.name}${up ? '+' : ''}</div>
      </div>
      <div class="card-art">${artHtml}</div>
      <div class="card-desc">${def.desc(up)}</div>
      <div class="card-type-tag">${typeLabel}</div>
    `;
    return div;
  }

  function updateHeaderBar() {
    floorEl.textContent = `${run.floor} / 12`;
    hpEl.textContent = `${run.hp} / ${run.maxHp}`;
    goldEl.textContent = `${run.gold}`;
    deckBtn.textContent = `🃏 Колода (${run.deck.length})`;

    if (!run.relics.length) {
      relicsEl.innerHTML = `<span style="color:var(--muted);font-size:0.8rem;">Реликвии: нет</span>`;
    } else {
      relicsEl.innerHTML = run.relics
        .map((rk) => `<span class="relic-badge" title="${RELIC_DB[rk].desc}">${RELIC_DB[rk].name}</span>`)
        .join('');
    }
  }

  // --- Боевая логика ---
  function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  function startCombat(nodeType) {
    const enemy = createEnemyForNode(nodeType, run.floor);
    combat = {
      nodeType,
      enemy,
      drawPile: shuffle(run.deck.map((c) => ({ ...c }))),
      hand: [],
      discardPile: [],
      energy: 3 + (run.relics.includes('mana_core') ? 1 : 0),
      maxEnergy: 3,
      heroBlock: run.relics.includes('yarn_ball') ? 4 : 0,
      heroStr: run.relics.includes('claw_stone') ? 1 : 0,
      metallicize: 0,
      turn: 1,
      log: `Бой начался: ${enemy.name}!`,
      busy: false,
      flashHero: false,
      flashEnemy: false,
    };
    const startDraw = 5 + (run.relics.includes('cat_grace') ? 1 : 0);
    drawCards(startDraw);
    run.screen = 'combat';
    renderAll();
  }

  function drawCards(count) {
    for (let i = 0; i < count; i++) {
      if (combat.drawPile.length === 0) {
        if (combat.discardPile.length === 0) break;
        combat.drawPile = shuffle(combat.discardPile);
        combat.discardPile = [];
      }
      if (combat.hand.length >= 9) break;
      combat.hand.push(combat.drawPile.pop());
    }
  }

  function calcHeroDamage(baseDmg) {
    let dmg = baseDmg + combat.heroStr;
    if (combat.enemy.vuln > 0) dmg = Math.floor(dmg * 1.5);
    return Math.max(0, dmg);
  }

  function applyDamageToEnemy(rawDmg) {
    let left = rawDmg;
    if (combat.enemy.block > 0) {
      const absorbed = Math.min(combat.enemy.block, left);
      combat.enemy.block -= absorbed;
      left -= absorbed;
    }
    combat.enemy.hp = Math.max(0, combat.enemy.hp - left);
    combat.flashEnemy = true;
  }

  function playCard(handIndex) {
    if (!combat || combat.busy) return;
    const cardObj = combat.hand[handIndex];
    const def = CARD_DB[cardObj.id];
    const up = Boolean(cardObj.up);
    const cost = up && def.upCost !== undefined ? def.upCost : def.cost;
    if (combat.energy < cost) return;

    combat.energy -= cost;
    combat.hand.splice(handIndex, 1);

    let logParts = [`Разыграно: ${def.name}${up ? '+' : ''}`];

    if (def.bodySlam) {
      const d = calcHeroDamage(combat.heroBlock);
      applyDamageToEnemy(d);
      logParts.push(`урон ${d}`);
    } else if (def.dmg) {
      const base = up && def.upDmg ? def.upDmg : def.dmg;
      const hits = def.hits || 1;
      for (let h = 0; h < hits; h++) {
        applyDamageToEnemy(calcHeroDamage(base));
      }
      logParts.push(`урон ${calcHeroDamage(base)}${hits > 1 ? 'x' + hits : ''}`);
    }

    if (def.blk) {
      const b = up && def.upBlk ? def.upBlk : def.blk;
      combat.heroBlock += b;
      logParts.push(`+${b} защиты`);
    }
    if (def.vuln) {
      const v = up && def.upVuln ? def.upVuln : def.vuln;
      combat.enemy.vuln += v;
    }
    if (def.weak) {
      const w = up && def.upWeak ? def.weak : def.weak;
      combat.enemy.weak += w;
    }
    if (def.poison) {
      const p = up && def.upPoison ? def.upPoison : def.poison;
      combat.enemy.poison += p;
    }
    if (def.selfStr) {
      const s = up && def.upStr ? def.upStr : def.selfStr;
      combat.heroStr += s;
    }
    if (def.metallicize) {
      const m = up && def.upMet ? def.upMet : def.metallicize;
      combat.metallicize += m;
    }
    if (def.energy) {
      combat.energy += def.energy;
    }
    if (def.heal) {
      const hl = up && def.upHeal ? def.upHeal : def.heal;
      run.hp = Math.min(run.maxHp, run.hp + hl);
    }
    if (def.draw) {
      drawCards(def.draw);
    }

    if (combat.enemy.hp <= 0 && def.bonusGold) {
      const g = up && def.upGold ? def.upGold : def.bonusGold;
      run.gold += g;
      logParts.push(`+${g} золота`);
    }

    const shouldExhaust = def.exhaust && !(cardObj.id === 'catnip_focus' && up);
    if (!shouldExhaust) combat.discardPile.push(cardObj);

    combat.log = logParts.join(' • ');

    if (combat.enemy.hp <= 0) {
      handleCombatVictory();
      return;
    }
    renderAll();
    combat.flashEnemy = false;
  }

  function endPlayerTurn() {
    if (!combat || combat.busy) return;
    combat.busy = true;
    combat.discardPile.push(...combat.hand);
    combat.hand = [];

    // Тик яда на враге
    if (combat.enemy.poison > 0) {
      combat.enemy.hp = Math.max(0, combat.enemy.hp - combat.enemy.poison);
      combat.enemy.poison = Math.max(0, combat.enemy.poison - 1);
      if (combat.enemy.hp <= 0) {
        handleCombatVictory();
        return;
      }
    }

    // Ход врага
    const intent = combat.enemy.pattern[combat.enemy.turnIdx % combat.enemy.pattern.length];
    combat.enemy.turnIdx += 1;
    combat.enemy.block = 0;

    let enemyMsg = `${combat.enemy.name}: ${intent.label}`;
    const dealHit = (raw) => {
      let dmg = raw + combat.enemy.str;
      if (combat.enemy.weak > 0) dmg = Math.floor(dmg * 0.75);
      dmg = Math.max(0, dmg);
      if (combat.heroBlock > 0) {
        const ab = Math.min(combat.heroBlock, dmg);
        combat.heroBlock -= ab;
        dmg -= ab;
      }
      if (dmg > 0) {
        run.hp = Math.max(0, run.hp - dmg);
        combat.flashHero = true;
      }
    };

    if (intent.type === 'attack') {
      dealHit(intent.val);
    } else if (intent.type === 'multi_attack') {
      for (let i = 0; i < intent.hits; i++) dealHit(intent.val);
    } else if (intent.type === 'defend_buff') {
      combat.enemy.block += intent.blk;
      combat.enemy.str += intent.str;
    } else if (intent.type === 'defend_atk') {
      combat.enemy.block += intent.blk;
      dealHit(intent.val);
    }

    if (combat.enemy.vuln > 0) combat.enemy.vuln -= 1;
    if (combat.enemy.weak > 0) combat.enemy.weak -= 1;

    if (run.hp <= 0) {
      run.screen = 'gameover';
      combat = null;
      saveRun();
      renderAll();
      return;
    }

    // Начало нового хода игрока
    combat.turn += 1;
    combat.energy = combat.maxEnergy;
    combat.heroBlock = combat.metallicize;
    combat.log = enemyMsg;
    drawCards(5);
    combat.busy = false;
    renderAll();
    combat.flashHero = false;
  }

  function handleCombatVictory() {
    if (run.relics.includes('vamp_fang')) {
      run.hp = Math.min(run.maxHp, run.hp + 4);
    }
    let goldEarned = combat.nodeType === 'elite' ? 35 : combat.nodeType === 'boss' ? 80 : 18 + run.floor * 2;
    if (run.relics.includes('lucky_bell')) goldEarned = Math.round(goldEarned * 1.3);
    run.gold += goldEarned;
    run.clearedFloor = run.floor;

    if (combat.nodeType === 'boss') {
      run.screen = 'victory';
      combat = null;
      saveRun();
      renderAll();
      return;
    }

    // Формируем награду: 3 случайные карты и реликвия с элиты
    const shuffledCards = shuffle([...REWARD_POOL]);
    run.rewardChoices = shuffledCards.slice(0, 3).map((id) => ({ id, up: Math.random() < 0.15 }));
    run.rewardRelic = null;
    if (combat.nodeType === 'elite') {
      const availRelics = Object.keys(RELIC_DB).filter((r) => !run.relics.includes(r));
      if (availRelics.length) {
        run.rewardRelic = availRelics[Math.floor(Math.random() * availRelics.length)];
      }
    }
    run.lastGoldEarned = goldEarned;
    combat = null;
    run.screen = 'reward';
    saveRun();
    renderAll();
  }

  function advanceFloor() {
    run.floor = Math.min(12, run.floor + 1);
    run.screen = 'map';
    saveRun();
    renderAll();
  }

  // --- Рендеры экранов ---
  function renderMap() {
    const wrap = document.createElement('div');
    wrap.className = 'map-container';
    wrap.innerHTML = `
      <div class="map-legend">
        <span>⚔️ Бой</span><span>💀 Элита (Реликвия)</span><span>🔥 Костёр</span><span>🛒 Лавка</span><span>👑 Босс (12 этаж)</span>
      </div>
      <div class="map-floors" id="mapFloorsBox"></div>
    `;
    const box = wrap.querySelector('#mapFloorsBox');

    run.map.forEach((nodes, idx) => {
      const fNum = idx + 1;
      const isCurrent = fNum === run.floor;
      const isVisited = fNum < run.floor;
      const row = document.createElement('div');
      row.className = `map-row${isCurrent ? ' current-row' : ''}`;
      row.innerHTML = `<div class="floor-num">Этаж ${fNum}</div>`;

      nodes.forEach((node) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `map-node${isCurrent ? ' available' : isVisited ? ' visited' : ''}`;
        btn.textContent = node.label;
        if (isCurrent) {
          btn.addEventListener('click', () => enterNode(node));
        } else {
          btn.disabled = true;
        }
        row.appendChild(btn);
      });
      box.appendChild(row);
    });
    stageEl.appendChild(wrap);
  }

  function enterNode(node) {
    run.visitedNodes.push(node.id);
    if (node.type === 'battle' || node.type === 'elite' || node.type === 'boss') {
      startCombat(node.type);
    } else if (node.type === 'camp') {
      run.screen = 'camp';
      saveRun();
      renderAll();
    } else if (node.type === 'shop') {
      const cards = shuffle([...REWARD_POOL]).slice(0, 3).map((id) => ({ id, up: false, price: 32 + Math.floor(Math.random() * 18) }));
      const availRelics = Object.keys(RELIC_DB).filter((r) => !run.relics.includes(r));
      const relic = availRelics.length ? { id: availRelics[0], price: 65 } : null;
      run.shopStock = { cards, relic, removedUsed: false };
      run.screen = 'shop';
      saveRun();
      renderAll();
    }
  }

  function renderCombat() {
    const en = combat.enemy;
    const intent = en.pattern[en.turnIdx % en.pattern.length];
    const heroPct = Math.round((run.hp / run.maxHp) * 100);
    const enPct = Math.round((en.hp / en.maxHp) * 100);

    const heroArt = VideoCatManager.getMediaHtml(0, run.floor, makeSvgArt('hero', '#34d399'));
    const enemyArt = VideoCatManager.getMediaHtml(en.seed, run.floor, makeSvgArt(en.art, '#fb7185'));

    const arena = document.createElement('div');
    arena.className = 'combat-arena';
    arena.innerHTML = `
      <div class="fighters-row">
        <div class="fighter-card${combat.flashHero ? ' hit-flash' : ''}">
          <div class="intent-pill defend">🐱 Кот-Авантюрист</div>
          <div class="portrait-frame">${heroArt}</div>
          <div class="hp-wrap">
            <div class="hp-fill hero" style="width:${heroPct}%"></div>
            <div class="hp-text">${run.hp} / ${run.maxHp} ОЗ</div>
          </div>
          <div class="status-pills">
            ${combat.heroBlock > 0 ? `<span class="st-tag block">🛡 Блок ${combat.heroBlock}</span>` : ''}
            ${combat.heroStr > 0 ? `<span class="st-tag str">💪 Сила +${combat.heroStr}</span>` : ''}
            ${combat.metallicize > 0 ? `<span class="st-tag block">⚙ Броня +${combat.metallicize}/ход</span>` : ''}
          </div>
        </div>

        <div class="vs-badge">VS<br><span style="font-size:0.75rem;font-weight:500;">Ход ${combat.turn}</span></div>

        <div class="fighter-card${combat.flashEnemy ? ' hit-flash' : ''}">
          <div class="intent-pill ${intent.type === 'defend_buff' ? 'defend' : ''}">Намерение: ${intent.label}</div>
          <div class="portrait-frame">${enemyArt}</div>
          <div style="font-weight:700;font-size:0.95rem;">${en.name}</div>
          <div class="hp-wrap">
            <div class="hp-fill" style="width:${enPct}%"></div>
            <div class="hp-text">${en.hp} / ${en.maxHp} ОЗ</div>
          </div>
          <div class="status-pills">
            ${en.block > 0 ? `<span class="st-tag block">🛡 Блок ${en.block}</span>` : ''}
            ${en.str > 0 ? `<span class="st-tag str">💪 Сила +${en.str}</span>` : ''}
            ${en.vuln > 0 ? `<span class="st-tag vuln">🎯 Уязвим ${en.vuln}</span>` : ''}
            ${en.weak > 0 ? `<span class="st-tag weak">📉 Слабость ${en.weak}</span>` : ''}
            ${en.poison > 0 ? `<span class="st-tag poison">☠ Яд ${en.poison}</span>` : ''}
          </div>
        </div>
      </div>

      <div class="turn-bar">
        <div class="energy-orb">⚡ Энергия: ${combat.energy} / ${combat.maxEnergy}</div>
        <div class="combat-log">${combat.log}</div>
        <div style="display:flex;gap:10px;align-items:center;">
          <span style="font-size:0.8rem;color:var(--muted);">Добор: ${combat.drawPile.length} | Сброс: ${combat.discardPile.length}</span>
          <button class="btn btn-amber" id="endTurnBtn" type="button">Закончить ход ⏭</button>
        </div>
      </div>

      <div class="hand-grid" id="handGrid"></div>
    `;

    arena.querySelector('#endTurnBtn').addEventListener('click', endPlayerTurn);
    const handGrid = arena.querySelector('#handGrid');
    combat.hand.forEach((cObj, idx) => {
      const cardEl = createCardElement(cObj, idx + 1 + combat.turn, false);
      cardEl.addEventListener('click', () => playCard(idx));
      handGrid.appendChild(cardEl);
    });

    stageEl.appendChild(arena);
  }

  function renderReward() {
    const div = document.createElement('div');
    div.className = 'choice-panel';
    div.innerHTML = `
      <h3 style="margin:0;color:var(--emerald);">🏆 Победа на этаже ${run.floor}! (+${run.lastGoldEarned || 20} 🪙)</h3>
      ${run.rewardRelic ? `<div>Получена реликвия: <span class="relic-badge">${RELIC_DB[run.rewardRelic].name}</span> — ${RELIC_DB[run.rewardRelic].desc}</div>` : ''}
      <p style="margin:0;color:var(--muted);">Выберите 1 новую карту в свою колоду или пропустите:</p>
      <div class="choice-grid" id="rewardCardsBox"></div>
      <button class="btn" id="skipRewardBtn" type="button">Пропустить и идти дальше ➡</button>
    `;

    if (run.rewardRelic && !run.relics.includes(run.rewardRelic)) {
      run.relics.push(run.rewardRelic);
      run.rewardRelic = null;
      updateHeaderBar();
    }

    const box = div.querySelector('#rewardCardsBox');
    run.rewardChoices.forEach((cObj, idx) => {
      const cEl = createCardElement(cObj, idx + 20, true);
      cEl.addEventListener('click', () => {
        run.deck.push(cObj);
        advanceFloor();
      });
      box.appendChild(cEl);
    });
    div.querySelector('#skipRewardBtn').addEventListener('click', advanceFloor);
    stageEl.appendChild(div);
  }

  function renderCamp() {
    const healAmt = Math.round(run.maxHp * 0.35);
    const div = document.createElement('div');
    div.className = 'choice-panel';
    div.innerHTML = `
      <h3 style="margin:0;color:var(--amber);">🔥 Костёр отдыха</h3>
      <p style="margin:0;color:var(--muted);">Восстановите силы перед следующими схватками или улучшите одну карту в колоде.</p>
      <div class="choice-grid">
        <button class="btn btn-primary" id="campRestBtn" type="button">❤️ Отдохнуть (+${healAmt} ОЗ)</button>
        <button class="btn btn-amber" id="campSmithBtn" type="button">⚒ Закалить карту (+)</button>
      </div>
    `;
    div.querySelector('#campRestBtn').addEventListener('click', () => {
      run.hp = Math.min(run.maxHp, run.hp + healAmt);
      advanceFloor();
    });
    div.querySelector('#campSmithBtn').addEventListener('click', () => {
      openDeckModal('Выберите карту для улучшения (+)', (idx) => {
        run.deck[idx].up = true;
        advanceFloor();
      });
    });
    stageEl.appendChild(div);
  }

  function renderShop() {
    const st = run.shopStock;
    const div = document.createElement('div');
    div.className = 'choice-panel';
    div.innerHTML = `
      <h3 style="margin:0;color:var(--cyan);">🛒 Подземная Лавка Кота-Торговца</h3>
      <p style="margin:0;color:var(--muted);">Ваше золото: <b>${run.gold} 🪙</b></p>
      <div class="choice-grid" id="shopGrid"></div>
      <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
        <button class="btn" id="shopRemoveBtn" type="button" ${st.removedUsed || run.gold < 40 || run.deck.length <= 5 ? 'disabled' : ''}>🗑 Удалить карту из колоды (40 🪙)</button>
        <button class="btn btn-primary" id="shopLeaveBtn" type="button">Покинуть лавку ➡</button>
      </div>
    `;

    const grid = div.querySelector('#shopGrid');
    st.cards.forEach((item, idx) => {
      if (!item) return;
      const wrap = document.createElement('div');
      wrap.className = 'shop-item';
      const cEl = createCardElement(item, idx + 30, true);
      const buyBtn = document.createElement('button');
      buyBtn.type = 'button';
      buyBtn.className = 'btn btn-sm btn-amber';
      buyBtn.textContent = `Купить (${item.price} 🪙)`;
      buyBtn.disabled = run.gold < item.price;
      buyBtn.addEventListener('click', () => {
        if (run.gold < item.price) return;
        run.gold -= item.price;
        run.deck.push({ id: item.id, up: item.up });
        st.cards[idx] = null;
        saveRun();
        renderAll();
      });
      wrap.appendChild(cEl);
      wrap.appendChild(buyBtn);
      grid.appendChild(wrap);
    });

    if (st.relic) {
      const rInfo = RELIC_DB[st.relic.id];
      const rBox = document.createElement('div');
      rBox.className = 'shop-item';
      rBox.innerHTML = `
        <div style="font-weight:700;color:var(--indigo);margin-top:8px;">${rInfo.name}</div>
        <div style="font-size:0.78rem;color:var(--muted);flex:1;">${rInfo.desc}</div>
      `;
      const rBtn = document.createElement('button');
      rBtn.type = 'button';
      rBtn.className = 'btn btn-sm btn-primary';
      rBtn.textContent = `Купить (${st.relic.price} 🪙)`;
      rBtn.disabled = run.gold < st.relic.price;
      rBtn.addEventListener('click', () => {
        if (run.gold < st.relic.price) return;
        run.gold -= st.relic.price;
        run.relics.push(st.relic.id);
        st.relic = null;
        saveRun();
        renderAll();
      });
      rBox.appendChild(rBtn);
      grid.appendChild(rBox);
    }

    div.querySelector('#shopRemoveBtn').addEventListener('click', () => {
      if (run.gold < 40 || st.removedUsed) return;
      openDeckModal('Выберите карту для удаления (40 🪙)', (idx) => {
        run.gold -= 40;
        run.deck.splice(idx, 1);
        st.removedUsed = true;
        saveRun();
        renderAll();
      });
    });

    div.querySelector('#shopLeaveBtn').addEventListener('click', advanceFloor);
    stageEl.appendChild(div);
  }

  function renderEndScreen(won) {
    const div = document.createElement('div');
    div.className = 'choice-panel';
    div.innerHTML = `
      <h2 style="margin:0;color:${won ? 'var(--emerald)' : 'var(--rose)'};">
        ${won ? '👑 ПОБЕДА! Древний Сфинкс повержен!' : '💀 Забег завершён на этаже ' + run.floor}
      </h2>
      <p style="margin:0;color:var(--muted);">
        Колода: ${run.deck.length} карт • Реликвий: ${run.relics.length} • Золото: ${run.gold} 🪙
      </p>
      <button class="btn btn-primary" id="restartEndBtn" type="button">🔄 Начать новый забег</button>
    `;
    div.querySelector('#restartEndBtn').addEventListener('click', newRun);
    stageEl.appendChild(div);
  }

  function renderAll() {
    updateHeaderBar();
    stageEl.innerHTML = '';
    if (run.screen === 'map') renderMap();
    else if (run.screen === 'combat') renderCombat();
    else if (run.screen === 'reward') renderReward();
    else if (run.screen === 'camp') renderCamp();
    else if (run.screen === 'shop') renderShop();
    else if (run.screen === 'victory') renderEndScreen(true);
    else renderEndScreen(false);
  }

  if (!loadRun()) newRun();
  else renderAll();

  VideoCatManager.init(() => {
    if (VideoCatManager.enabled) renderAll();
  });
})();
