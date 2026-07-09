// Account export helpers (TXT + PDF) for the inbounds page.
//
// Builds a "card" per selected account and renders it either as a styled plain-text
// file or as a PDF (via the vendored jsPDF UMD build). A QR code is drawn only for
// accounts that have a real share-link URI (xray protocols); VPN accounts
// (L2TP/PPTP/OpenVPN) have no URI, so they get the card without a QR.
const AccountExport = {
  // --- data ------------------------------------------------------------------

  // buildCards turns [{inboundId, email}] targets into renderable card objects,
  // reusing the page app for inbound lookup, stats and link generation.
  buildCards(app, targets) {
    const cards = [];
    for (const t of targets) {
      // One malformed account must not abort the whole export — guard each card
      // and skip (with a console note) any that throws while being built.
      try {
        const dbInbound = app.dbInbounds.find(r => r.id === t.inboundId);
        if (!dbInbound) continue;
        const inbound = dbInbound.toInbound();
        const clients = app.getInboundClients(dbInbound) || [];
        const client = clients.find(c => c.email === t.email);
        if (!client) continue;

        const server = (inbound.listen && inbound.listen !== '0.0.0.0')
          ? inbound.listen : location.hostname;

        // xray protocols produce a share link; VPN protocols return ''.
        let link = '';
        try {
          const all = inbound.genAllLinks('', app.remarkModel || '-ieo', client);
          link = (all && all[0] && all[0].link) ? all[0].link : '';
        } catch (e) { link = ''; }

        let used = '';
        try { used = SizeFormatter.sizeFormat(app.getSumStats(dbInbound, client.email) || 0); }
        catch (e) { used = '0'; }

        cards.push({
          remark: dbInbound.remark || inbound.remark || '',
          protocol: (dbInbound.protocol || '').toUpperCase(),
          network: AccountExport._network(dbInbound, inbound),
          server: server,
          port: AccountExport._portText(dbInbound, inbound),
          email: client.email || '',
          password: client.password || '',
          uuid: (client.id && client.id !== client.password) ? client.id : '',
          psk: AccountExport._psk(dbInbound, inbound),
          expiry: AccountExport._expiryText(client.expiryTime),
          used: used,
          total: client.totalGB > 0 ? SizeFormatter.sizeFormat(client.totalGB) : '∞',
          enable: !!client.enable,
          link: link,
        });
      } catch (e) {
        if (typeof console !== 'undefined') console.warn('export: skipped account', t, e);
      }
    }
    return cards;
  },

  _network(dbInbound, inbound) {
    if (dbInbound.isOpenvpn) {
      const s = inbound.settings || {};
      const parts = [];
      if (s.udpEnable) parts.push('UDP');
      if (s.tcpEnable) parts.push('TCP');
      return parts.join('/') || 'UDP';
    }
    if (dbInbound.isL2tp) return inbound.settings && inbound.settings.ipsec ? 'IPsec/PSK' : 'raw';
    if (dbInbound.isPptp) return 'MPPE';
    if (inbound.stream) {
      const p = [inbound.stream.network];
      if (inbound.stream.isTls) p.push('TLS');
      if (inbound.stream.isReality) p.push('Reality');
      return p.filter(Boolean).join('/');
    }
    return '';
  },

  _portText(dbInbound, inbound) {
    if (dbInbound.isOpenvpn) {
      const s = inbound.settings || {};
      const parts = [];
      if (s.udpEnable) parts.push('UDP ' + (inbound.port));
      if (s.tcpEnable) parts.push('TCP ' + (s.tcpPort));
      return parts.join('  ') || String(inbound.port);
    }
    return String(inbound.port);
  },

  _psk(dbInbound, inbound) {
    if (dbInbound.isL2tp && inbound.settings && inbound.settings.ipsec) {
      return inbound.settings.psk || '';
    }
    return '';
  },

  _expiryText(expiryTime) {
    if (!expiryTime || expiryTime === 0) return '∞';
    if (expiryTime < 0) {
      const days = Math.round(Math.abs(expiryTime) / 86400000);
      return 'delayed start (' + days + 'd)';
    }
    try { return IntlUtil.formatDate(expiryTime); }
    catch (e) { return new Date(expiryTime).toLocaleString(); }
  },

  // --- TXT -------------------------------------------------------------------

  txt(cards, filename) {
    const W = 52;
    const line = (label, val) =>
      val === '' || val === undefined || val === null
        ? null
        : '  ' + (label + ' :').padEnd(12, ' ') + ' ' + val;
    const bars = '═'.repeat(W);
    const dash = '─'.repeat(W);
    const blocks = cards.map(c => {
      const rows = [
        line('Server', c.server + ':' + c.port),
        line('Protocol', c.protocol + (c.network ? ' / ' + c.network : '')),
        line('Username', c.email),
        line('Password', c.password),
        line('UUID', c.uuid),
        line('PSK', c.psk),
        line('Expiry', c.expiry),
        line('Traffic', c.used + ' / ' + c.total),
        line('Status', c.enable ? 'Enabled' : 'Disabled'),
        line('Link', c.link),
      ].filter(Boolean);
      const title = ('  ' + (c.remark || c.email)).padEnd(W, ' ');
      return [bars, title, dash, rows.join('\n'), bars].join('\n');
    });
    const header = 'VPN Accounts — ' + cards.length + ' account(s)\nGenerated ' + new Date().toLocaleString() + '\n\n';
    FileManager.downloadTextFile(header + blocks.join('\n\n') + '\n', (filename || 'accounts') + '.txt', { type: 'text/plain' });
  },

  // --- PDF -------------------------------------------------------------------

  pdf(cards, filename) {
    if (!window.jspdf || !window.jspdf.jsPDF) {
      alert('PDF library not loaded');
      return;
    }
    const doc = new window.jspdf.jsPDF({ unit: 'pt', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 32;
    const cardW = pageW - margin * 2;
    const pad = 14;
    const lineH = 16;

    // Page title.
    let y = margin;
    doc.setFont('helvetica', 'bold'); doc.setFontSize(16);
    doc.setTextColor(40, 40, 40);
    doc.text('VPN Accounts', margin, y + 6);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9);
    doc.setTextColor(130, 130, 130);
    doc.text(cards.length + ' account(s) — ' + new Date().toLocaleString(), margin, y + 22);
    y += 44;

    for (const c of cards) {
      const rows = [
        ['Server', c.server + ':' + c.port],
        ['Protocol', c.protocol + (c.network ? '  /  ' + c.network : '')],
        ['Username', c.email],
        c.password ? ['Password', c.password] : null,
        c.uuid ? ['UUID', c.uuid] : null,
        c.psk ? ['PSK', c.psk] : null,
        ['Expiry', c.expiry],
        ['Traffic', c.used + '  /  ' + c.total],
        ['Status', c.enable ? 'Enabled' : 'Disabled'],
      ].filter(Boolean);

      const qr = c.link ? AccountExport._qrDataUrl(c.link) : '';
      const qrSize = qr ? 96 : 0;
      const bodyRows = rows.length + (c.link ? 1 : 0);
      const bodyH = Math.max(bodyRows * lineH, qrSize);
      const cardH = 30 /*header band*/ + pad + bodyH + pad;

      // New page if this card won't fit.
      if (y + cardH > pageH - margin) { doc.addPage(); y = margin; }

      // Card background + header band.
      doc.setDrawColor(224, 224, 224); doc.setFillColor(250, 250, 250);
      doc.roundedRect(margin, y, cardW, cardH, 6, 6, 'FD');
      doc.setFillColor(c.enable ? 124 : 176, c.enable ? 77 : 176, c.enable ? 255 : 176);
      doc.roundedRect(margin, y, cardW, 30, 6, 6, 'F');
      doc.rect(margin, y + 16, cardW, 14, 'F'); // square off the band's bottom corners
      doc.setTextColor(255, 255, 255); doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
      doc.text(AccountExport._clip(doc, c.remark || c.email, cardW - pad * 2 - 90), margin + pad, y + 20);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9);
      doc.text(c.protocol + (c.network ? ' · ' + c.network : ''), margin + cardW - pad, y + 20, { align: 'right' });

      // Body rows.
      let ry = y + 30 + pad + 4;
      const labelX = margin + pad;
      const valX = margin + pad + 78;
      const valMaxW = cardW - pad * 2 - 78 - (qr ? qrSize + 12 : 0);
      doc.setFontSize(10);
      for (const [label, val] of rows) {
        doc.setTextColor(140, 140, 140); doc.setFont('helvetica', 'normal');
        doc.text(label, labelX, ry);
        doc.setTextColor(40, 40, 40); doc.setFont('helvetica', 'bold');
        doc.text(AccountExport._clip(doc, String(val), valMaxW), valX, ry);
        ry += lineH;
      }
      if (c.link) {
        doc.setTextColor(140, 140, 140); doc.setFont('helvetica', 'normal');
        doc.text('Link', labelX, ry);
        doc.setTextColor(90, 90, 90); doc.setFontSize(7);
        doc.text(AccountExport._clip(doc, c.link, valMaxW), valX, ry);
        doc.setFontSize(10);
      }
      // QR on the right.
      if (qr) {
        doc.addImage(qr, 'PNG', margin + cardW - pad - qrSize, y + 30 + pad, qrSize, qrSize);
      }

      y += cardH + 16;
    }

    doc.save((filename || 'accounts') + '.pdf');
  },

  _qrDataUrl(text) {
    try { return new QRious({ value: text, size: 240, level: 'M' }).toDataURL('image/png'); }
    catch (e) { return ''; }
  },

  _clip(doc, text, maxW) {
    if (!text) return '';
    if (doc.getTextWidth(text) <= maxW) return text;
    let t = text;
    while (t.length > 1 && doc.getTextWidth(t + '…') > maxW) t = t.slice(0, -1);
    return t + '…';
  },
};
