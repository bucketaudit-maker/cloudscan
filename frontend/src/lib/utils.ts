/** Format bytes to human-readable string */
export function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/** Format number with locale separators */
export function formatNumber(n: number | undefined): string {
  if (!n && n !== 0) return '—';
  return n.toLocaleString();
}

/** Relative time ago string */
export function timeAgo(dateStr: string | undefined): string {
  if (!dateStr) return '—';
  const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (diff < 0) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 2592000) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

/** Provider display info */
export const PROVIDERS: Record<string, { label: string; color: string; textColor: string }> = {
  aws: { label: 'AWS S3', color: '#ff9900', textColor: '#000' },
  azure: { label: 'Azure Blob', color: '#0078d4', textColor: '#fff' },
  gcp: { label: 'GCP Storage', color: '#4285f4', textColor: '#fff' },
  digitalocean: { label: 'DO Spaces', color: '#0080ff', textColor: '#fff' },
  alibaba: { label: 'Alibaba OSS', color: '#ff6a00', textColor: '#fff' },
};

/** File extension icons */
export const EXT_ICONS: Record<string, string> = {
  sql: '🗄️', csv: '📊', json: '📋', yaml: '⚙️', yml: '⚙️', xml: '📄',
  pdf: '📕', docx: '📘', xlsx: '📗', zip: '📦', gz: '📦', tar: '📦',
  env: '🔑', key: '🔐', pem: '🔐', pub: '🔐', sh: '🖥️', py: '🐍',
  js: '📜', css: '🎨', html: '🌐', log: '📝', md: '📝', ini: '⚙️',
  tfstate: '🏗️', tfvars: '🏗️', bak: '💾', sqlite: '🗄️', parquet: '📊',
  php: '🐘', rb: '💎', txt: '📄', conf: '⚙️', htpasswd: '🔐',
};

export function getExtIcon(ext: string): string {
  return EXT_ICONS[ext?.toLowerCase()] || '📄';
}

/** AI Classification colors */
export const CLASSIFICATION_COLORS: Record<string, { color: string; label: string }> = {
  credentials: { color: '#f04848', label: 'Credentials' },
  pii: { color: '#ff6b35', label: 'PII' },
  financial: { color: '#f5a623', label: 'Financial' },
  medical: { color: '#e74c9e', label: 'Medical' },
  infrastructure: { color: '#4a9eff', label: 'Infrastructure' },
  source_code: { color: '#9b59b6', label: 'Source Code' },
  database: { color: '#3498db', label: 'Database' },
  generic: { color: '#4a5f73', label: 'Generic' },
};

/** Risk level colors */
export const RISK_COLORS: Record<string, { bg: string; color: string }> = {
  critical: { bg: '#f04848', color: '#fff' },
  high: { bg: '#ff6b35', color: '#fff' },
  medium: { bg: '#f5a623', color: '#000' },
  low: { bg: '#4a9eff', color: '#fff' },
  info: { bg: '#4a5f73', color: '#fff' },
};
