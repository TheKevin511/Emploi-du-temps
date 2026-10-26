/**
 * Génération du PDF de l'emploi du temps (A4 paysage), aux couleurs du thème choisi.
 * Dépendance : pdf-lib (100 % JavaScript, aucun binaire à installer).
 */
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

/* ==========================================================================
   Constantes
   ========================================================================== */
const DAYS = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi', 'Dimanche'];
const FIRST_HOUR = 8;
const LAST_HOUR = 23;
const HOUR_COUNT = LAST_HOUR - FIRST_HOUR + 1;

const PAGE_WIDTH = 841.89; // A4 paysage, en points
const PAGE_HEIGHT = 595.28;
const MARGIN = 28;
const PANEL_PADDING = 8;
const TITLE_HEIGHT = 52;
const FOOTER_HEIGHT = 18;
const HEADER_HEIGHT = 22;
const LABEL_WIDTH = 40;
const GAP = 3;
const CELL_FONT_SIZE = 7.5;
const CELL_LEADING = 9;

const DEFAULT_THEME_ID = 'plum';

/* ==========================================================================
   Thèmes (mêmes couleurs que la page web)
   ========================================================================== */
const LIGHT_CELLS = ['#cfe0f0', '#cfe3c8', '#e0d0ee', '#ffd9a8', '#f6c6c0', '#f7e29a', '#bfe3df', '#e4d9c8'];
const DARK_CELLS = ['#2f4660', '#33503a', '#4a3a63', '#6b4a22', '#6b3a35', '#675a22', '#25595a', '#45392c'];
const PLUM_CELLS = ['#d2e4f4', '#d3eedc', '#ecd9ea', '#f8dfc4', '#f8d7de', '#f6ebb8', '#cdebf0', '#ebe4d8'];

const THEMES = {
  plum:     { bg: '#f7f4f8', card: '#ffffff', ink: '#3e1139', muted: '#5d6579', accent: '#7b2574', accentText: '#ffffff', empty: '#f1e8f0', hour: '#e9d9e7', cells: PLUM_CELLS, cellText: '#14192b' },
  light:    { bg: '#fff0d2', card: '#fff9ea', ink: '#7b5230', muted: '#a07a52', accent: '#7b5230', accentText: '#fff6e3', empty: '#fbe7bf', hour: '#f4d9a3', cells: LIGHT_CELLS, cellText: '#4a2f17' },
  dark:     { bg: '#1c1511', card: '#2b2018', ink: '#f1dcb8', muted: '#c0a584', accent: '#e9c58c', accentText: '#2a1c10', empty: '#35271d', hour: '#40301f', cells: DARK_CELLS, cellText: '#f6e8d0' },
  midnight: { bg: '#0f1624', card: '#18223a', ink: '#dbe6ff', muted: '#93a5cc', accent: '#8fb3ff', accentText: '#0c1426', empty: '#202c47', hour: '#263556', cells: DARK_CELLS, cellText: '#f6e8d0' },
  ocean:    { bg: '#e6f4fb', card: '#f6fcff', ink: '#17517a', muted: '#4f87ab', accent: '#17517a', accentText: '#f2fbff', empty: '#d3ebf7', hour: '#b5dcf0', cells: LIGHT_CELLS, cellText: '#4a2f17' },
  forest:   { bg: '#e9f3e3', card: '#f6fbf2', ink: '#2f5a34', muted: '#628a64', accent: '#2f5a34', accentText: '#f3fbef', empty: '#d9ebd0', hour: '#bddcaf', cells: LIGHT_CELLS, cellText: '#4a2f17' },
  rose:     { bg: '#ffe8ef', card: '#fff6f9', ink: '#8a2f55', muted: '#b96a8a', accent: '#8a2f55', accentText: '#fff3f7', empty: '#fbd8e4', hour: '#f6bcd0', cells: LIGHT_CELLS, cellText: '#4a2f17' },
  lavender: { bg: '#f0eafc', card: '#faf7ff', ink: '#52358a', muted: '#8468b8', accent: '#52358a', accentText: '#f7f3ff', empty: '#e4daf7', hour: '#d1c0f0', cells: LIGHT_CELLS, cellText: '#4a2f17' },
  slate:    { bg: '#f1f3f6', card: '#ffffff', ink: '#2a3140', muted: '#6b7385', accent: '#2a3140', accentText: '#ffffff', empty: '#eceff3', hour: '#dde2ea', cells: LIGHT_CELLS, cellText: '#4a2f17' },
};

/* ==========================================================================
   Utilitaires de dessin
   ========================================================================== */
const toRgb = (hex) => {
  const value = parseInt(hex.slice(1), 16);
  return rgb(((value >> 16) & 255) / 255, ((value >> 8) & 255) / 255, (value & 255) / 255);
};

const roundedPath = (width, height, radius) =>
  `M ${radius} 0 H ${width - radius} Q ${width} 0 ${width} ${radius} ` +
  `V ${height - radius} Q ${width} ${height} ${width - radius} ${height} ` +
  `H ${radius} Q 0 ${height} 0 ${height - radius} V ${radius} Q 0 0 ${radius} 0 Z`;

// Retire les caractères que les polices standard du PDF ne savent pas afficher (emojis, etc.).
const sanitize = (font, text) =>
  Array.from(String(text ?? ''))
    .filter((char) => {
      try {
        font.encodeText(char);
        return true;
      } catch {
        return false;
      }
    })
    .join('')
    .trim();

const truncateToWidth = (text, font, size, maxWidth) => {
  let result = text;
  while (result.length > 1 && font.widthOfTextAtSize(result, size) > maxWidth) {
    result = `${result.slice(0, -2)}…`;
  }
  return result;
};

const wrapText = (text, font, size, maxWidth, maxLines) => {
  const lines = [];
  let line = '';

  for (const word of text.split(/\s+/).filter(Boolean)) {
    const candidate = line ? `${line} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, size) <= maxWidth) {
      line = candidate;
    } else {
      if (line) lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);

  const visible = lines.slice(0, Math.max(1, maxLines));
  if (lines.length > visible.length) visible[visible.length - 1] += '…';
  return visible.map((item) => truncateToWidth(item, font, size, maxWidth));
};

/* ==========================================================================
   Génération du PDF
   ========================================================================== */
export const buildPlanPdf = async ({ name = '', cells = [], themeId } = {}) => {
  const theme = THEMES[themeId] ?? THEMES[DEFAULT_THEME_ID];

  const pdf = await PDFDocument.create();
  pdf.setTitle('Emploi du temps');
  pdf.setCreator('Mon Planning');

  const page = pdf.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);

  /* --- Primitives de dessin (coordonnées mesurées depuis le haut de la page) --- */
  const fillRect = (x, top, width, height, radius, color) => {
    page.drawSvgPath(roundedPath(width, height, radius), { x, y: PAGE_HEIGHT - top, color: toRgb(color) });
  };

  const drawText = (text, x, baselineTop, { font = regular, size = 10, color = theme.ink, align = 'left' } = {}) => {
    const width = font.widthOfTextAtSize(text, size);
    const offset = align === 'right' ? -width : align === 'center' ? -width / 2 : 0;
    page.drawText(text, { x: x + offset, y: PAGE_HEIGHT - baselineTop, size, font, color: toRgb(color) });
  };

  const drawCenteredLines = (lines, x, top, width, height, font, color) => {
    const blockHeight = lines.length * CELL_LEADING;
    const startTop = top + (height - blockHeight) / 2;
    lines.forEach((line, index) => {
      const baseline = startTop + index * CELL_LEADING + (CELL_LEADING + CELL_FONT_SIZE * 0.7) / 2;
      drawText(line, x + width / 2, baseline, { font, size: CELL_FONT_SIZE, color, align: 'center' });
    });
  };

  /* --- Géométrie de la grille --- */
  const panelTop = MARGIN + TITLE_HEIGHT;
  const panelBottom = PAGE_HEIGHT - MARGIN - FOOTER_HEIGHT;
  const innerLeft = MARGIN + PANEL_PADDING;
  const innerTop = panelTop + PANEL_PADDING;
  const innerWidth = PAGE_WIDTH - 2 * (MARGIN + PANEL_PADDING);
  const innerHeight = panelBottom - panelTop - 2 * PANEL_PADDING;

  const dayWidth = (innerWidth - LABEL_WIDTH - DAYS.length * GAP) / DAYS.length;
  const rowHeight = (innerHeight - HEADER_HEIGHT - GAP - (HOUR_COUNT - 1) * GAP) / HOUR_COUNT;

  const columnX = (day) => innerLeft + LABEL_WIDTH + GAP + day * (dayWidth + GAP);
  const rowTop = (hour) => innerTop + HEADER_HEIGHT + GAP + (hour - FIRST_HOUR) * (rowHeight + GAP);

  /* --- Fond et en-tête --- */
  page.drawRectangle({ x: 0, y: 0, width: PAGE_WIDTH, height: PAGE_HEIGHT, color: toRgb(theme.bg) });

  drawText('Emploi du temps', MARGIN, MARGIN + 20, { font: bold, size: 22 });
  drawText('Semaine type · de 8h à minuit', MARGIN, MARGIN + 38, { size: 9.5, color: theme.muted });

  const owner = sanitize(bold, name);
  if (owner) drawText(owner, PAGE_WIDTH - MARGIN, MARGIN + 18, { font: bold, size: 15, align: 'right' });
  const today = new Date().toLocaleDateString('fr-FR');
  drawText(`Généré le ${today}`, PAGE_WIDTH - MARGIN, MARGIN + 36, { size: 8.5, color: theme.muted, align: 'right' });

  fillRect(MARGIN, panelTop, PAGE_WIDTH - 2 * MARGIN, panelBottom - panelTop, 14, theme.card);

  /* --- Jours --- */
  DAYS.forEach((dayName, day) => {
    fillRect(columnX(day), innerTop, dayWidth, HEADER_HEIGHT, 6, theme.accent);
    drawText(dayName, columnX(day) + dayWidth / 2, innerTop + 14.5, {
      font: bold, size: 9, color: theme.accentText, align: 'center',
    });
  });

  /* --- Heures et cases vides --- */
  const activities = new Map(cells.map((cell) => [`${cell.day}-${cell.hour}`, cell]));
  const isCovered = (day, hour) =>
    [1, 2, 3].some((offset) => (activities.get(`${day}-${hour - offset}`)?.dur ?? 0) > offset);

  for (let hour = FIRST_HOUR; hour <= LAST_HOUR; hour++) {
    fillRect(innerLeft, rowTop(hour), LABEL_WIDTH, rowHeight, 6, theme.hour);
    drawText(`${hour}h00`, innerLeft + LABEL_WIDTH / 2, rowTop(hour) + rowHeight / 2 + 2.8, {
      font: bold, size: 8, align: 'center',
    });

    DAYS.forEach((_, day) => {
      if (!isCovered(day, hour) && !activities.has(`${day}-${hour}`)) {
        fillRect(columnX(day), rowTop(hour), dayWidth, rowHeight, 6, theme.empty);
      }
    });
  }

  /* --- Activités (une case peut s'étendre sur plusieurs heures) --- */
  cells.forEach(({ day, hour, title, color, dur }) => {
    const span = Math.min(dur, LAST_HOUR + 1 - hour);
    const height = span * rowHeight + (span - 1) * GAP;
    const x = columnX(day);
    const top = rowTop(hour);

    fillRect(x, top, dayWidth, height, 6, theme.cells[(color - 1) % theme.cells.length]);

    const text = sanitize(bold, title);
    const maxLines = Math.floor((height - 4) / CELL_LEADING);
    const lines = wrapText(text, bold, CELL_FONT_SIZE, dayWidth - 10, maxLines);
    drawCenteredLines(lines, x, top, dayWidth, height, bold, theme.cellText);
  });

  /* --- Pied de page --- */
  drawText('Mon Planning', PAGE_WIDTH / 2, PAGE_HEIGHT - MARGIN + 2, { size: 7.5, color: theme.muted, align: 'center' });

  return pdf.save();
};