const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/airport.json'), 'utf8'));
const {main, makeGroups, makeRuleProviders, makeRules} = require('../configs/clash-verge-script.js');

function airport() {
  return structuredClone(fixture);
}

test('enhances an airport profile while preserving non-reserved state', () => {
  const config = airport();
  config['socks-port'] = 7891;
  config['log-level'] = 'info';
  config.dns['cache-algorithm'] = 'arc';
  const output = main(config);

  assert.equal(output['mixed-port'], 7890);
  assert.equal(output['socks-port'], 7891);
  assert.equal(output['log-level'], 'info');
  assert.deepEqual(output.proxies, fixture.proxies);
  assert.deepEqual(output['proxy-providers'], fixture['proxy-providers']);
  assert.ok(output['proxy-groups'].some(group => group.name === 'Airport-Chain'));
  assert.ok(output['proxy-groups'].some(group => group.name === 'PRX-Proxy'));
  assert.deepEqual(output['rule-providers']['Airport-Rules'], fixture['rule-providers']['Airport-Rules']);
  assert.equal(output.tun.enable, false);
  assert.equal(output.tun.stack, 'gvisor');
  assert.deepEqual(output.tun['dns-hijack'], ['any:53']);
  assert.equal(output.dns['cache-algorithm'], 'arc');
  assert.equal(output.ipv6, false);
  assert.equal(output.rules.at(-1), 'MATCH,PRX-Proxy');
  assert.equal(output.rules.includes('MATCH,DIRECT'), false);
  assert.deepEqual(output.rules, makeRules());
});

test('uses one proxied resolver path and a direct encrypted bootstrap path', () => {
  const output = main(airport());

  assert.deepEqual(output.dns.nameserver, ['https://1.1.1.1/dns-query#PRX-Proxy']);
  assert.deepEqual(output.dns['default-nameserver'], ['https://1.1.1.1/dns-query#DIRECT']);
  assert.deepEqual(output.dns['proxy-server-nameserver'], ['https://1.1.1.1/dns-query#DIRECT']);
  assert.equal(output.dns.enable, true);
  assert.equal(output.dns.ipv6, false);
  assert.equal(output.dns['enhanced-mode'], 'fake-ip');
  assert.equal(output.dns['use-hosts'], false);
  assert.equal(output.dns['use-system-hosts'], false);
  assert.equal(output.dns['respect-rules'], true);
  for (const key of ['fallback', 'fallback-filter', 'nameserver-policy', 'direct-nameserver']) {
    assert.equal(key in output.dns, false, `stale DNS key ${key}`);
  }
});

test('creates complete dynamic groups without silently direct-routing AI or UDP', () => {
  const groups = makeGroups();
  const byName = Object.fromEntries(groups.map(group => [group.name, group]));

  for (const name of ['PRX-Manual', 'PRX-Auto']) {
    assert.equal(byName[name]['include-all'], true);
    assert.equal(byName[name]['exclude-filter'], '(?i)剩余|流量|套餐|到期|官网|更新|订阅|客服|expire|traffic|website');
  }
  assert.deepEqual(byName['PRX-AI'].proxies, ['PRX-Manual', 'PRX-Auto']);
  assert.equal('disable-udp' in byName['PRX-Proxy'], false);
  assert.equal('udp' in byName['PRX-Proxy'], false);
});

test('uses public, unique, tracked rule-provider assets through PRX-Proxy', () => {
  const providers = makeRuleProviders();
  const paths = new Set();
  const urls = new Set();

  for (const provider of Object.values(providers)) {
    assert.equal(provider.type, 'http');
    assert.equal(provider.format, 'yaml');
    assert.equal(provider.interval, 86400);
    assert.equal(provider.proxy, 'PRX-Proxy');
    assert.ok(provider.url.startsWith('https://raw.githubusercontent.com/jwenwen233/proxy-rules/main/dist/mihomo/'));
    assert.equal(paths.has(provider.path), false, `duplicate provider path ${provider.path}`);
    paths.add(provider.path);
    assert.equal(urls.has(provider.url), false, `duplicate provider URL ${provider.url}`);
    urls.add(provider.url);
    const basename = path.basename(new URL(provider.url).pathname);
    assert.ok(fs.statSync(path.join(__dirname, '..', 'dist', 'mihomo', basename)).isFile());
  }
});

test('puts embedded AI handling before provider and reject rules before the final proxy match', () => {
  const rules = makeRules();
  const firstProvider = rules.findIndex(rule => rule.startsWith('RULE-SET,'));
  const aiRule = 'DOMAIN-SUFFIX,openai.com,PRX-AI';

  assert.ok(rules.indexOf(aiRule) >= 0);
  assert.ok(rules.indexOf(aiRule) < firstProvider);
  assert.ok(rules.indexOf('RULE-SET,PRX-RULE-reject-domain,REJECT') > rules.indexOf('RULE-SET,PRX-RULE-direct,DIRECT'));
  assert.deepEqual(rules.slice(-2), ['GEOIP,CN,DIRECT,no-resolve', 'MATCH,PRX-Proxy']);
});

test('rejects reserved airport proxy, group, and provider names', () => {
  for (const change of [
    config => config.proxies.push({name: 'PRX-Node'}),
    config => config['proxy-groups'].push({name: 'PRX-Group'}),
    config => { config['proxy-providers']['PRX-Provider'] = {type: 'file'}; },
    config => { config['rule-providers']['PRX-Rules'] = {type: 'file'}; },
  ]) {
    const config = airport();
    change(config);
    assert.throws(() => main(config), /reserved PRX- name/);
  }
});
