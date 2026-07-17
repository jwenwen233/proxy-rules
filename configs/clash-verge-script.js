const PREFIX = 'PRX-';
const RAW = 'https://raw.githubusercontent.com/jwenwen233/proxy-rules/main/dist/mihomo';
const INFO_FILTER = '(?i)剩余|流量|套餐|到期|官网|更新|订阅|客服|expire|traffic|website';

const SELECT_GROUPS = {
  'PRX-AI': ['PRX-Manual', 'PRX-Auto'],
  'PRX-Media': ['PRX-Manual', 'PRX-Auto'],
  'PRX-Messaging': ['PRX-Manual', 'PRX-Auto'],
  'PRX-Apple-Microsoft': ['DIRECT', 'PRX-Manual', 'PRX-Auto'],
  'PRX-Proxy': ['PRX-Manual', 'PRX-Auto'],
};

const PROVIDERS = {
  'PRX-RULE-direct': ['classical', 'direct.yaml'],
  'PRX-RULE-reject-domain': ['domain', 'reject-domain.yaml'],
  'PRX-RULE-ai': ['classical', 'ai.yaml'],
  'PRX-RULE-openai-voice-ip': ['ipcidr', 'openai-voice-ip.yaml'],
  'PRX-RULE-media': ['domain', 'media.yaml'],
  'PRX-RULE-messaging': ['domain', 'messaging.yaml'],
  'PRX-RULE-apple-microsoft': ['domain', 'apple-microsoft.yaml'],
  'PRX-RULE-cn-domain': ['domain', 'cn-domain.yaml'],
  'PRX-RULE-cn-ip': ['ipcidr', 'cn-ip.yaml'],
};

function assertNoReservedNames(config) {
  const names = [
    ...(config.proxies || []).map(item => item.name),
    ...(config['proxy-groups'] || []).map(item => item.name),
    ...Object.keys(config['proxy-providers'] || {}),
    ...Object.keys(config['rule-providers'] || {}),
  ];
  const collision = names.find(name => typeof name === 'string' && name.startsWith(PREFIX));
  if (collision) throw new Error(`reserved ${PREFIX} name in airport profile: ${collision}`);
}

function makeGroups() {
  return [
    {
      name: 'PRX-Manual', type: 'select', 'include-all': true,
      'exclude-filter': INFO_FILTER,
    },
    {
      name: 'PRX-Auto', type: 'url-test', 'include-all': true,
      'exclude-filter': INFO_FILTER, url: 'https://www.gstatic.com/generate_204',
      interval: 600, timeout: 5000, tolerance: 100,
    },
    ...Object.entries(SELECT_GROUPS).map(([name, proxies]) => ({name, type: 'select', proxies})),
  ];
}

function makeRuleProviders() {
  return Object.fromEntries(Object.entries(PROVIDERS).map(([name, [behavior, file]]) => [name, {
    type: 'http', behavior, format: 'yaml', interval: 86400, proxy: 'PRX-Proxy',
    path: `./ruleset/prx-${file}`, url: `${RAW}/${file}`,
  }]));
}

function makeRules() {
  return [
    'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
    'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,169.254.0.0/16,DIRECT,no-resolve',
    'DOMAIN-SUFFIX,local,DIRECT',
    'DOMAIN-SUFFIX,todesk.com,DIRECT',
    'DOMAIN-SUFFIX,todesk.cn,DIRECT',
    'DOMAIN-SUFFIX,scnet.cn,DIRECT',
    'PROCESS-NAME,ToDesk,DIRECT',
    'DOMAIN-SUFFIX,anthropic.com,PRX-AI',
    'DOMAIN-SUFFIX,claude.ai,PRX-AI',
    'DOMAIN-SUFFIX,claude.com,PRX-AI',
    'DOMAIN-SUFFIX,openai.com,PRX-AI',
    'DOMAIN-SUFFIX,chatgpt.com,PRX-AI',
    'DOMAIN-SUFFIX,oaistatic.com,PRX-AI',
    'DOMAIN-SUFFIX,oaiusercontent.com,PRX-AI',
    'RULE-SET,PRX-RULE-direct,DIRECT',
    'RULE-SET,PRX-RULE-reject-domain,REJECT',
    'RULE-SET,PRX-RULE-ai,PRX-AI',
    'RULE-SET,PRX-RULE-openai-voice-ip,PRX-AI,no-resolve',
    'RULE-SET,PRX-RULE-messaging,PRX-Messaging',
    'RULE-SET,PRX-RULE-media,PRX-Media',
    'RULE-SET,PRX-RULE-apple-microsoft,PRX-Apple-Microsoft',
    'RULE-SET,PRX-RULE-cn-domain,DIRECT',
    'RULE-SET,PRX-RULE-cn-ip,DIRECT,no-resolve',
    'GEOIP,CN,DIRECT,no-resolve',
    'MATCH,PRX-Proxy',
  ];
}

function main(config) {
  assertNoReservedNames(config);

  const {
    fallback, 'fallback-filter': fallbackFilter,
    'nameserver-policy': nameserverPolicy,
    'direct-nameserver': directNameserver,
    ...dnsRuntime
  } = config.dns || {};
  config.ipv6 = false;
  config.dns = {
    ...dnsRuntime,
    enable: true,
    ipv6: false,
    'enhanced-mode': 'fake-ip',
    'use-hosts': false,
    'use-system-hosts': false,
    'respect-rules': true,
    nameserver: ['https://1.1.1.1/dns-query#PRX-Proxy'],
    'default-nameserver': ['https://1.1.1.1/dns-query#DIRECT'],
    'proxy-server-nameserver': ['https://1.1.1.1/dns-query#DIRECT'],
    'fake-ip-filter': ['*.lan', '*.local', 'localhost.ptlogin2.qq.com', 'captive.apple.com'],
  };
  config.tun = {...(config.tun || {}), 'dns-hijack': ['any:53']};
  config['proxy-groups'] = [...(config['proxy-groups'] || []), ...makeGroups()];
  config['rule-providers'] = {...(config['rule-providers'] || {}), ...makeRuleProviders()};
  config.rules = makeRules();
  return config;
}

if (typeof module !== 'undefined') {
  module.exports = {main, makeGroups, makeRuleProviders, makeRules};
}
