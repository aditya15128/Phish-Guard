const TARGET_BRANDS = [
  'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'instagram',
  'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'bankofamerica', 'hsbc',
  'linkedin', 'twitter', 'github', 'dropbox', 'adobe', 'office365', 'outlook'
];

const SUSPICIOUS_TLDS = [
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online', 'site',
  'work', 'date', 'loan', 'racing', 'download', 'stream', 'science'
];

const SHORTENERS = [
  'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'bc.vc', 'shorte.st', 'cutt.ly', 'rebrand.ly'
];

function calculateEntropy(str) {
  const freq = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function extractFeatures(url) {
  const parsed = new URL(url);
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;

  return {
    hasIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname),
    hasCredentials: /https?:\/\/[^\/]*@/.test(url),
    hasAtInPath: pathname.includes('@'),
    hasMultipleSubdomains: hostname.split('.').length > 3,
    maxSubdomainLength: Math.max(...hostname.split('.').map(s => s.length)),
    urlLength: url.length,
    hostnameLength: hostname.length,
    brandInSubdomain: TARGET_BRANDS.some(b =>
      hostname.includes(b) && !hostname.endsWith('.' + b + '.com') && !hostname.endsWith('.' + b)
    ),
    brandInPath: TARGET_BRANDS.some(b => pathname.toLowerCase().includes(b)),
    suspiciousTld: SUSPICIOUS_TLDS.some(tld => hostname.endsWith('.' + tld)),
    isShortener: SHORTENERS.some(s => hostname.includes(s)),
    hasHomograph: /[\u0400-\u04FF\u0370-\u03FF]/.test(hostname),
    excessiveHyphens: (hostname.match(/-/g) || []).length >= 3,
    excessiveDigits: (hostname.match(/\d/g) || []).length / hostname.length > 0.3,
    entropy: calculateEntropy(hostname.replace(/\./g, '')),
    isHttp: parsed.protocol === 'http:',
    isDataUri: url.startsWith('data:'),
  };
}

const SCORING_RULES = [
  { feature: 'hasIpAddress', weight: 40, reason: 'IP address used instead of domain' },
  { feature: 'hasCredentials', weight: 35, reason: 'Credentials embedded in URL' },
  { feature: 'hasAtInPath', weight: 25, reason: '@ symbol in path (obfuscation)' },
  { feature: 'brandInSubdomain', weight: 30, reason: 'Brand name in subdomain (impersonation)' },
  { feature: 'brandInPath', weight: 15, reason: 'Brand name in URL path' },
  { feature: 'suspiciousTld', weight: 20, reason: 'High-risk TLD (.tk, .xyz, etc.)' },
  { feature: 'isShortener', weight: 15, reason: 'URL shortener hiding destination' },
  { feature: 'hasHomograph', weight: 35, reason: 'Homograph attack (lookalike characters)' },
  { feature: 'excessiveHyphens', weight: 10, reason: 'Excessive hyphens in domain' },
  { feature: 'excessiveDigits', weight: 10, reason: 'High digit ratio in domain' },
  { feature: 'isHttp', weight: 10, reason: 'Insecure HTTP (not HTTPS)' },
  { feature: 'isDataUri', weight: 50, reason: 'Data URI scheme (bypasses filters)' },
];

function scoreContinuousFeatures(features) {
  let score = 0;
  const triggers = [];

  if (features.entropy > 4.0) { score += 25; triggers.push(`High entropy (${features.entropy.toFixed(2)})`); }
  else if (features.entropy > 3.5) { score += 15; triggers.push(`Elevated entropy (${features.entropy.toFixed(2)})`); }
  else if (features.entropy > 3.0) { score += 5; }

  if (features.hasMultipleSubdomains) {
    const count = new URL(features.url).hostname.split('.').length - 2;
    if (count >= 4) { score += 20; triggers.push(`${count} subdomains`); }
    else if (count === 3) { score += 10; triggers.push('3 subdomains'); }
  }

  if (features.maxSubdomainLength > 30) { score += 15; triggers.push('Very long subdomain'); }
  else if (features.maxSubdomainLength > 20) { score += 8; triggers.push('Long subdomain'); }

  if (features.urlLength > 150) { score += 10; triggers.push('Very long URL'); }
  else if (features.urlLength > 100) { score += 5; triggers.push('Long URL'); }

  return { score, triggers };
}

export function scoreUrl(url) {
  const features = extractFeatures(url);
  let score = 0;
  const triggered = [];

  for (const rule of SCORING_RULES) {
    if (features[rule.feature]) {
      score += rule.weight;
      triggered.push({ feature: rule.feature, reason: rule.reason, weight: rule.weight });
    }
  }

  const continuous = scoreContinuousFeatures({ ...features, url });
  score += continuous.score;
  triggered.push(...continuous.triggers.map(t => ({ feature: 'continuous', reason: t, weight: 0 })));

  let riskLevel = 'safe';
  if (score >= 50) riskLevel = 'critical';
  else if (score >= 30) riskLevel = 'high';
  else if (score >= 15) riskLevel = 'medium';
  else if (score >= 5) riskLevel = 'low';

  return {
    score,
    triggered,
    features,
    isPhishing: score >= 30,
    riskLevel,
    timestamp: Date.now()
  };
}

export function getExplanation(result) {
  if (!result.triggered.length) return 'No suspicious patterns detected.';
  return result.triggered.map(t => `• ${t.reason} (+${t.weight})`).join('\n');
}