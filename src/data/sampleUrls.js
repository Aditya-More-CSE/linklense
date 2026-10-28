/**
 * Safe demonstration URLs using RFC 2606 / RFC 6761 reserved example domains
 * (example.com, example.org, example.net) and RFC 5737 documentation IP ranges (192.0.2.0/24).
 * None of these will contact external servers or live malicious hosts.
 */
export const SAMPLE_URLS = [
  {
    id: 'safe-https',
    label: 'Normal-looking URL',
    tag: 'Normal',
    url: 'https://docs.example.com/resources/getting-started',
    description: 'A standard HTTPS web page with clean structure.'
  },
  {
    id: 'userinfo-trick',
    label: 'Suspicious URL structure',
    tag: 'Suspicious Structure',
    url: 'https://account.bank.example.com@credential-harvest.example.net/auth',
    description: 'Text before "@" masquerades as a trusted bank hostname.'
  },
  {
    id: 'ip-literal',
    label: 'Unusual hostname',
    tag: 'Unusual Hostname',
    url: 'http://192.0.2.88:8443/system/gateway',
    description: 'Direct IPv4 documentation address rather than a domain name.'
  },
  {
    id: 'punycode-domain',
    label: 'Punycode (IDN)',
    tag: 'Punycode',
    url: 'https://xn--pple-43d.example.com/devices/portal',
    description: 'Internationalized domain name containing "xn--" representation.'
  },
  {
    id: 'shortener-link',
    label: 'Known Shortener',
    tag: 'Obscured',
    url: 'https://bit.ly/sample-shortener-redirect',
    description: 'Registrable domain matches a known URL shortening service.'
  },
  {
    id: 'redirect-param',
    label: 'External Redirect',
    tag: 'Redirect Param',
    url: 'https://portal.example.com/oauth/return?dest=https%3A%2F%2Fexternal-login.example.net%2Fclaim',
    description: 'Query parameter contains an encoded external destination.'
  },
  {
    id: 'deep-subdomain',
    label: 'Deep Subdomain + Urgency',
    tag: 'Pattern Alert',
    url: 'https://login.secure.verify-account.portal.example.org/urgent-auth?token=auth99',
    description: 'Deep subdomain nesting with urgency/credential keywords.'
  },
  {
    id: 'http-insecure',
    label: 'Plain HTTP',
    tag: 'Insecure Transport',
    url: 'http://info.example.org/company/overview',
    description: 'Plain HTTP lacking transport encryption.'
  }
];
