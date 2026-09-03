import { canonicalizeUrl } from '../src/services/analysis/canonicalization';

describe('Layer 0: URL Canonicalization Engine', () => {
  it('should normalize scheme to lowercase and prepend http:// if missing', () => {
    const res1 = canonicalizeUrl('EXAMPLE.COM/login');
    expect(res1.protocol).toBe('http:');
    expect(res1.hostname).toBe('example.com');
    expect(res1.canonicalUrl).toBe('http://example.com/login');

    const res2 = canonicalizeUrl('HTTPS://Secure-Bank.com/');
    expect(res2.protocol).toBe('https:');
    expect(res2.hostname).toBe('secure-bank.com');
  });

  it('should strip default ports 80 and 443 while preserving non-standard ports', () => {
    const res80 = canonicalizeUrl('http://example.com:80/test');
    expect(res80.port).toBeNull();
    expect(res80.canonicalUrl).toBe('http://example.com/test');

    const res443 = canonicalizeUrl('https://example.com:443/test');
    expect(res443.port).toBeNull();
    expect(res443.canonicalUrl).toBe('https://example.com/test');

    const res8080 = canonicalizeUrl('http://example.com:8080/test');
    expect(res8080.port).toBe(8080);
    expect(res8080.canonicalUrl).toBe('http://example.com:8080/test');
  });

  it('should handle Punycode / IDN internationalized domain names', () => {
    const res = canonicalizeUrl('http://xn--pypal-4ve.com/signin');
    expect(res.isPunycode).toBe(true);
    expect(res.hostname).toBe('xn--pypal-4ve.com');
  });

  it('should strip trailing dots in hostnames', () => {
    const res = canonicalizeUrl('https://paypal.com./login');
    expect(res.hostname).toBe('paypal.com');
    expect(res.canonicalUrl).toBe('https://paypal.com/login');
  });

  it('should collapse redundant duplicate slashes in pathname', () => {
    const res = canonicalizeUrl('https://example.com///path//to///file.php');
    expect(res.pathname).toBe('/path/to/file.php');
    expect(res.canonicalUrl).toBe('https://example.com/path/to/file.php');
  });
});
