import { useEffect, useState } from "react";

import { caStatus, proxyStatus, type CaStatus, type ProxyStatus } from "../ipc";

/**
 * Mobile app testing, from the network side.
 *
 * A phone's traffic is just traffic, so the proxy and the CA that already read a
 * browser's HTTPS read an app's too — the work is pointing the device at them and
 * trusting the certificate. This view is the setup for that, plus the parts of a mobile
 * assessment that live off the wire (pinning, the binary, local storage) said plainly so
 * nobody mistakes an intercepting proxy for the whole job.
 */
export function MobileView() {
  const [proxy, setProxy] = useState<ProxyStatus | null>(null);
  const [ca, setCa] = useState<CaStatus | null>(null);

  useEffect(() => {
    proxyStatus().then(setProxy).catch(() => undefined);
    caStatus().then(setCa).catch(() => undefined);
  }, []);

  const listen = proxy?.address ?? null;
  const port = listen?.split(":").pop() ?? "8080";

  return (
    <div className="mobile">
      <header className="dash-head">
        <div>
          <h1>Mobile app testing</h1>
          <p className="muted">
            Route a device's traffic through Nullhawk's proxy and trust its certificate,
            and every tool here — history, repeater, scanner, authz — works on the app's
            API the same as on a website.
          </p>
        </div>
      </header>

      <section className="card">
        <h2>1 · Point the device at the proxy</h2>
        {proxy?.running ? (
          <p className="muted">
            The proxy is listening on <code>{listen}</code>. On the device's Wi-Fi
            settings set a <strong>manual HTTP proxy</strong> to this machine's LAN IP
            and port <code>{port}</code>.
          </p>
        ) : (
          <p className="notice warn">
            The proxy is not running. Start it on the <strong>Setup</strong> tab first,
            then come back.
          </p>
        )}
        <ul className="steps">
          <li>
            <strong>Android</strong> — Settings → Wi-Fi → long-press the network → Modify →
            Advanced → Proxy: Manual → host = this machine's LAN IP, port = {port}.
          </li>
          <li>
            <strong>iOS</strong> — Settings → Wi-Fi → (i) → Configure Proxy → Manual →
            Server = LAN IP, Port = {port}.
          </li>
          <li className="muted small">
            The listen address above is local to this machine; a phone needs the machine's
            IP on the same network (e.g. <code>192.168.x.x</code>), not <code>127.0.0.1</code>.
          </li>
        </ul>
      </section>

      <section className="card">
        <h2>2 · Trust the CA certificate</h2>
        {ca ? (
          <>
            <dl className="facts">
              <dt>Fingerprint</dt>
              <dd className="mono small">{ca.fingerprint}</dd>
              <dt>Certificate</dt>
              <dd className="mono small">{ca.directory}</dd>
              <dt>On this machine</dt>
              <dd className={ca.trusted ? "ok" : "muted"}>
                {ca.trusted ? "trusted" : "not in the system store"}
              </dd>
            </dl>
            <ul className="steps">
              <li>
                Copy the <code>.crt</code> from the certificate directory to the device
                (email, a served file, or <code>adb push</code>).
              </li>
              <li>
                <strong>Android</strong> — Settings → Security → Encryption &amp;
                credentials → Install a certificate → CA certificate. Note: since Android
                7, apps trust <em>user</em> CAs only if their network-security config opts
                in — otherwise the app must be patched or run on a rooted device with the
                CA in the system store.
              </li>
              <li>
                <strong>iOS</strong> — install the profile, then Settings → General →
                About → Certificate Trust Settings and enable full trust for it.
              </li>
            </ul>
          </>
        ) : (
          <p className="muted">Certificate details are unavailable — open a project first.</p>
        )}
      </section>

      <section className="card">
        <h2>3 · Certificate pinning</h2>
        <p className="muted">
          A pinned app rejects even a trusted CA, so interception shows nothing until the
          pin is defeated. That is done off Nullhawk, on the device or the binary:
        </p>
        <ul className="steps">
          <li>
            <strong>Frida / objection</strong> — <code>objection --gadget &lt;app&gt;
            explore</code> then <code>android sslpinning disable</code> (or the iOS
            equivalent) on a rooted/jailbroken device or a re-signed build.
          </li>
          <li>
            <strong>Patch the app</strong> — repackage the APK with a network-security
            config that trusts user CAs, or hook the pinning class.
          </li>
          <li className="muted small">
            These use external tooling. Once the pin is down, the traffic lands in History
            like any other.
          </li>
        </ul>
      </section>

      <section className="card">
        <h2>4 · Off the wire</h2>
        <p className="muted">
          Interception covers the network. A full mobile assessment also looks at what the
          proxy never sees — and some of it comes back here:
        </p>
        <ul className="steps">
          <li>
            <strong>The binary</strong> — decompile the APK/IPA (jadx, apktool, unzip) and
            paste the strings into the <strong>Toolkit → Secret &amp; endpoint miner</strong>
            to pull hardcoded keys, endpoints and versioned libraries out of it.
          </li>
          <li>
            <strong>Local storage</strong> — shared preferences, SQLite, keychain/keystore
            entries, cached files: check for tokens and PII stored in the clear.
          </li>
          <li>
            <strong>Platform surface</strong> — exported activities/services, deep links
            and app-links, WebView <code>addJavascriptInterface</code>, cleartext-traffic
            flags, backup flags.
          </li>
          <li>
            <strong>The API</strong> — once traffic is flowing, treat it as any web API:
            replay as other identities on the Authorization tab, fuzz parameters, scan.
          </li>
        </ul>
      </section>
    </div>
  );
}
