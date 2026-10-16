"""Self-contained PenX terminal report stylesheet."""

TERMINAL_CSS = r"""
:root{--bg:#09090b;--panel:#111216;--ink:#eef0f5;--muted:#a0a2b3;--line:#505057;--magenta:#e00bd4;--green:#25e45c;--cyan:#43c9f2}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;color:var(--ink);background:var(--bg);font:13px/1.6 Consolas,"Lucida Console","Courier New",monospace}
.container{max-width:1170px;margin:auto;padding:26px 28px 40px}
.topbar{display:flex;justify-content:space-between;align-items:end;gap:18px;padding-bottom:16px;border-bottom:1px solid #777780}
.brand{display:flex;flex-direction:column;gap:7px;min-width:0}
.brandmark{display:none}
.brandname{display:inline-block;font:bold clamp(60px,10vw,108px)/.95 Consolas,"Courier New",monospace;letter-spacing:-10px;color:var(--magenta);text-shadow:3px 4px #070508,6px 7px #8c0085,8px 9px #0e0911;-webkit-text-stroke:1px #ed33e5}
.brandname em{font-style:normal;color:inherit}
.brandcap{color:var(--muted);font-size:12px}
.top-meta{color:var(--muted);font-size:11px;text-align:right}
.top-meta strong{display:block;margin-top:5px;color:var(--magenta);font-size:15px}
.hero{display:flex;justify-content:space-between;align-items:center;gap:20px;padding:24px 0 20px}
.hero>div:first-child{min-width:0;flex:1}
.host-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:14px}
.host-item{min-width:0;border:1px solid #464650;background:#111216;padding:7px 10px;overflow-wrap:anywhere}
.host-item small{display:block;color:var(--green);text-transform:uppercase;font-size:10px}
.host-item strong{display:block;font-size:12px;color:#e5e7ef;font-weight:normal}
.coverage-note{border-left:3px solid #ebd738;padding:6px 10px;background:#1d1a12}

.eyebrow{font-size:11px;color:var(--green);font-weight:bold;letter-spacing:1px}
.hero h1{font-size:clamp(20px,3vw,27px);letter-spacing:-.6px;margin:7px 0;overflow-wrap:anywhere}
.hero p{font-size:11px;color:var(--muted);margin:0}
.risk-panel{flex:0 0 190px;border:1px dashed #72717d;background:#0b0c0f;padding:11px 14px;text-align:center}
.risk-panel span{font-size:11px;color:var(--muted);display:block}
.risk-panel strong{display:block;margin:8px 0 0;padding:6px;font-size:22px;color:var(--risk-color,var(--green));border:1px solid var(--risk-color,var(--green))}
.metadata{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));background:var(--panel);border:1px solid var(--line);margin-bottom:17px}
.meta{min-width:0;padding:12px 15px;border-right:1px solid #37373f}
.meta:last-child{border:0}
.meta small{font-size:10px;color:var(--muted);text-transform:uppercase;display:block}
.meta strong{font-size:12px;font-weight:normal;display:block;margin-top:4px;overflow-wrap:anywhere}
.overview{background:var(--panel);border:1px solid var(--line);padding:15px 18px;margin-bottom:20px}
.overview-header{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid var(--line);padding-bottom:8px}
.overview-header h2{margin:0;font-size:15px;color:var(--green);text-transform:uppercase}
.overview-header h2:before{content:"[+] "}
.mono{font-size:10px;color:var(--muted)}
.overview p{font-size:12px;color:#b9bdc8;margin:10px 0 17px}
.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:9px}
.metric{min-width:0;background:#0a0b0d;border:1px solid var(--line);border-left:3px solid var(--sev,#abb3c2);padding:10px 12px}
.metric span{font-size:11px;font-weight:bold;display:block;color:var(--sev,#bac1d0)}
.metric strong{font-size:27px;display:block;line-height:1.3;color:var(--sev,#bac1d0)}
.metric-critical{--sev:#ff3754}.metric-high{--sev:#ff9051}.metric-medium{--sev:#ebd738}.metric-low{--sev:#39c4f2}.metric-info{--sev:#b5becf}
.report-filters{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 15px;color:var(--muted);font-size:12px}
.report-filters label{cursor:pointer;border:1px solid var(--line);padding:5px 10px}
.report-filters input{accent-color:var(--green)}
section#findings:has(.report-filters label:nth-child(2) input:checked) .finding:not(.status-confirmed){display:none}
section#findings:has(.report-filters label:nth-child(3) input:checked) .finding:not(.status-potential){display:none}
@media print{.report-filters{display:none}}
.evidence{margin-top:10px}
.evidence pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;padding:10px;color:var(--muted);font-size:11px}
.evidence small{display:block;color:var(--muted);padding:0 10px 9px}
.comparison-text{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--panel);border:1px solid var(--line);padding:14px;font:12px/1.7 Consolas,monospace;color:var(--ink)}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:15px 0 27px}
nav a{border:1px solid #41434b;background:#0f1115;padding:6px 10px;text-decoration:none;color:#b6bccb;font-size:11px}
nav a:hover,nav a:focus{color:var(--green);border-color:var(--green)}
section{margin:0 0 29px;scroll-margin-top:18px}
.section-head{display:flex;align-items:baseline;gap:9px;padding:0 0 5px;margin:0 0 12px;border-bottom:1px solid #686a74}
.section-no{font-size:15px;color:var(--green);font-weight:bold}
.section-head h2{font-size:15px;color:var(--green);text-transform:uppercase;letter-spacing:.6px;margin:0}
.section-head small{font-size:11px;color:var(--muted);margin-left:auto}
.findings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.recommendations-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.finding,.rec,.record{margin:0 0 10px;min-width:0;border:1px solid var(--line);border-left:3px solid var(--sev,#24db6e);background:#101215;padding:13px 15px;overflow-wrap:anywhere;break-inside:avoid}
.findings-grid .finding,.recommendations-grid .rec{margin:0}
.finding.severity-critical,.sev-critical{--sev:#ff3b57}
.finding.severity-high,.sev-high{--sev:#ff9051}
.finding.severity-medium,.sev-medium{--sev:#ebd738}
.finding.severity-low,.sev-low{--sev:#39c4f2}
.finding.severity-info,.sev-info{--sev:#b8c4d5}
.finding.severity-unknown,.sev-unknown{--sev:#8994a5}
.finding-top{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.finding-top h3{margin:0;flex:1;min-width:160px;font-size:13px;line-height:1.5}
.item-number,.rec-index{color:var(--sev,var(--magenta));font-weight:bold}
.finding-meta{display:flex;flex-wrap:wrap;gap:7px;margin:9px 0}
.finding-meta span{border:1px solid #42434c;padding:3px 7px;font-size:11px;color:#b4b9c8}
.finding p,.rec p,.record p{font-size:12px;color:#b9becb;white-space:pre-wrap;margin:7px 0 0}
.badge{color:var(--sev,#b7bac5);font-size:11px;font-weight:bold}
.badge:before{content:"["}.badge:after{content:"]"}
.rec{display:flex;gap:12px;border-left-color:var(--cyan)}
.rec h3,.record h3{font-size:13px;margin:0;color:var(--cyan)}
.record.review{border-color:#804c81;border-left-color:var(--magenta)}
.record.review h3{color:var(--magenta)}
.detail-row{display:grid;grid-template-columns:100px minmax(0,1fr);gap:12px;margin-top:9px;padding-top:9px;border-top:1px solid #383940;white-space:pre-wrap;color:#bbc0cd}
.detail-label{font-size:11px;color:var(--muted);text-transform:uppercase}
.empty{border:1px dashed #484955;padding:15px;color:var(--muted);background:#111216}
details{border:1px dashed #60636f;background:#0e0f11}
details summary{padding:12px 14px;cursor:pointer;list-style:none;color:#b2b4c2}
details summary::-webkit-details-marker{display:none}
details summary:before{content:"▶ ";color:var(--green)}
details[open] summary:before{content:"▼ "}
.log{border-top:1px solid #44454f;padding:16px;max-height:520px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.6 Consolas,"Courier New",monospace;color:#a6a9b8}
.caution{font-size:12px;color:#d39aa7;margin:0 0 10px}
footer{border-top:1px solid #686a74;padding:15px 0 0;display:flex;flex-wrap:wrap;gap:15px;justify-content:space-between;color:var(--muted);font-size:11px}
a{color:#e68fe3}
@media(min-width:821px) and (max-width:1080px){.findings-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:820px){.container{padding:20px 16px}.topbar{align-items:start}.brandname{font-size:64px;letter-spacing:-7px}.hero{flex-direction:column;align-items:stretch}.host-grid{grid-template-columns:1fr}.risk-panel{flex:0 0 auto}.metadata{grid-template-columns:1fr}.meta{border-right:0;border-bottom:1px solid var(--line)}.metrics{grid-template-columns:repeat(3,minmax(0,1fr))}.findings-grid,.recommendations-grid{grid-template-columns:1fr}.top-meta{display:none}}
@media print{
 @page{size:A4;margin:12mm}
 body{background:#fff!important;color:#171922!important;font-size:10px}
 .container{max-width:none;padding:0}
 .brandname{color:#a0009f!important;text-shadow:none;-webkit-text-stroke:0;font-size:55px}
 .topbar,.section-head,footer{border-color:#8a8e9b}
 .brandcap,.top-meta,.hero p,.meta small,.mono,.caution,.finding p,.rec p,.record p,.overview p{color:#3d424d!important}
 .hero{padding:12px 0}
 .metadata,.overview,.finding,.rec,.record,.empty,.metric,details,.host-item{background:white!important;color:#171922!important;border-color:#858995}
 .overview-header h2,.section-head h2,.section-no{color:#078b32!important}
 .finding-top h3,.rec h3,.record h3,.meta strong,.detail-row{color:#20232a!important}
 .finding-meta span{color:#454953;border-color:#c2c6ce}
 nav{display:none}
 .metrics{grid-template-columns:repeat(5,minmax(0,1fr))}
 .log{max-height:none;overflow:visible;color:#3a3e48}
 details .log{display:block}
 .finding,.rec,.record{break-inside:avoid}
}
/* Security dashboard enhancement; fully self-contained and print-friendly. */
body{font-family:Inter,"Segoe UI",Arial,sans-serif;line-height:1.62}
.brandname,.brandcap,.eyebrow,.top-meta,.host-item,.meta,.metric,.item-number,.rec-index,.section-no,.scanner-chip strong,.comparison-text,.log{font-family:Consolas,"Courier New",monospace}
.container{max-width:1260px}
.hero{align-items:stretch;gap:18px}
.hero>div:first-child{padding:22px;border:1px solid #393d49;background:linear-gradient(145deg,#171922,#101115);border-radius:12px}
.hero h1{font-size:clamp(22px,3vw,34px)}
.hero-status{margin:12px 0 0;border:1px solid #656040;color:#f3dc8c;display:inline-block;padding:5px 10px;font:11px Consolas,monospace}
.risk-panel{border-style:solid;border-radius:12px;background:linear-gradient(160deg,#151c18,#0c110f);display:flex;flex-direction:column;justify-content:center;min-width:185px}
.host-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.host-item{border-color:#393d49;background:#1c1e26;border-radius:7px}
.metadata{border-radius:10px;overflow:hidden}
.overview{border-radius:12px;padding:22px}
.executive-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:15px 0 20px}
.overview-tile{background:#191c24;border:1px solid #3b3d49;border-radius:9px;padding:16px;display:flex;flex-direction:column;gap:7px}
.overview-tile strong{font:700 32px Consolas,monospace;color:#edf1f6}
.overview-tile span{font-size:11px;color:#aeb8c7;text-transform:uppercase;letter-spacing:.5px}
.coverage-panel{padding:18px 20px;border:1px solid #454955;background:#13151b;border-radius:12px}
.coverage-intro{color:#aeb8c7;font-size:12px}
.metric-caption{font:11px/1.5 Consolas,"Courier New",monospace;color:#aeb8c7;margin:3px 0 8px}
.scanner-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}
.scanner-chip{display:flex;align-items:center;gap:10px;background:#1c1e26;border:1px solid #383d48;border-radius:7px;padding:10px 12px;min-width:0}
.scanner-chip span:nth-child(2){overflow-wrap:anywhere}
.scanner-chip strong{margin-left:auto;color:#aeb8c7;font-size:10px}
.scanner-state{width:9px;height:9px;flex:0 0 9px;border-radius:50%}
.state-ok{background:#32dd79;box-shadow:0 0 8px #32dd7955}
.state-failed{background:#ffa34c;box-shadow:0 0 8px #ffa34c55}
nav{position:sticky;top:0;z-index:10;background:#09090bf0;padding:10px 0;border-bottom:1px solid #383c45;backdrop-filter:blur(10px)}
nav a{border-radius:6px}
.finding,.rec,.record{border-radius:9px}
.rec{padding:18px;gap:15px}
.rec-content{min-width:0}
.rec-kind{font:10px Consolas,monospace;color:#8eabd0;letter-spacing:.6px}
.rec h3{font-size:14px;margin:6px 0 0}
.rec p{font-size:13px;line-height:1.7}
@media(max-width:820px){.executive-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.scanner-grid{grid-template-columns:1fr}.hero>div:first-child{padding:15px}nav{position:static}}

/* SL#14-15 live report refinements: compact header and stable card sizing. */
.topbar{align-items:center;padding-bottom:10px}
.brandname{font-size:clamp(50px,7vw,72px);letter-spacing:-6px}
.brandcap{max-width:580px;line-height:1.5}
.hero{padding:12px 0 14px}
.hero>div:first-child{padding:16px}
.hero h1{font-size:clamp(21px,2.4vw,29px)}
.metadata{grid-template-columns:repeat(4,minmax(0,1fr))}
.meta{padding:10px 12px}
.findings-grid{grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))}
.rec{align-items:flex-start}
.rec-index{flex:none;white-space:nowrap;min-width:50px}
.rec-content{flex:1;min-width:0}
.risk-explanation{font-size:12px;color:var(--muted);line-height:1.65}
@media(max-width:820px){.brandname{font-size:52px;letter-spacing:-5px}.metadata{grid-template-columns:repeat(2,minmax(0,1fr))}.hero>div:first-child{padding:15px}.findings-grid{grid-template-columns:1fr}}
@media(max-width:480px){.metadata{grid-template-columns:1fr}.executive-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media print{.topbar,.hero{break-inside:avoid}.brandname{font-size:48px}.metadata{grid-template-columns:repeat(4,minmax(0,1fr))}.rec-index{white-space:nowrap}}

@media print{nav{display:none}.coverage-panel,.overview-tile,.scanner-chip,.hero>div:first-child{background:white!important;color:#161a24!important;border-color:#9a9dab}.overview-tile strong,.overview-tile span,.scanner-chip strong{color:#20232a!important}.executive-metrics{grid-template-columns:repeat(4,minmax(0,1fr))}}

"""