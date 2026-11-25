/* Legacy core: what the file holds, cleaning, and the checks that keep secrets out of it. No DOM, no network. */
(function(root){
"use strict";
var KINDS={
  role:[["executor","Executor"],["alt-executor","Backup executor"],["poa-property","Power of attorney, property"],["poa-care","Power of attorney, personal care"],["guardian","Guardian for children"],["lawyer","Lawyer"],["accountant","Accountant"],["advisor","Financial advisor"],["family","Family"],["other","Other"]],
  doc:[["will","Will"],["poa-property","Power of attorney, property"],["poa-care","Power of attorney, personal care"],["living-will","Living will / care wishes"],["trust","Trust"],["marriage","Marriage or separation papers"],["deed","Property deed"],["tax","Tax returns"],["other","Other"]],
  ins:[["life","Life"],["group-life","Life, through work"],["disability","Disability"],["critical","Critical illness"],["mortgage","Mortgage"],["home","Home or tenant"],["auto","Car"],["travel","Travel"],["other","Other"]],
  acct:[["bank","Chequing or savings"],["tfsa","TFSA"],["rrsp","RRSP or RRIF"],["fhsa","FHSA"],["resp","RESP"],["pension","Work pension"],["gov","CPP / OAS"],["nonreg","Non-registered"],["crypto","Crypto"],["other","Other"]]
};
/* Lists that differ by country (Canada is the default above). Saved values from any country keep their labels. */
var KINDS_BY={
  US:{role:[["executor","Executor"],["alt-executor","Backup executor"],["poa-property","Power of attorney, finances"],["poa-care","Health care agent / proxy"],["guardian","Guardian for children"],["trustee","Trustee"],["lawyer","Lawyer"],["accountant","Accountant (CPA)"],["advisor","Financial advisor"],["family","Family"],["other","Other"]],
    doc:[["will","Will"],["trust","Living trust"],["poa-property","Durable power of attorney, finances"],["poa-care","Health care proxy"],["living-will","Living will / advance directive"],["marriage","Marriage or divorce papers"],["deed","Property deed"],["tax","Tax returns"],["other","Other"]],
    acct:[["bank","Checking or savings"],["k401","401(k) / 403(b)"],["ira","IRA or Roth IRA"],["hsa","HSA"],["p529","529 plan"],["brokerage","Brokerage"],["pension","Work pension"],["gov","Social Security"],["crypto","Crypto"],["other","Other"]],
    ins:[["life","Life"],["group-life","Life, through work"],["disability","Disability"],["ltc","Long-term care"],["mortgage","Mortgage"],["home","Home or renters"],["auto","Car"],["health","Health"],["other","Other"]]},
  IN:{role:[["executor","Executor"],["alt-executor","Backup executor"],["poa-property","Power of attorney holder"],["nominee","Nominee"],["guardian","Guardian for children"],["lawyer","Lawyer"],["accountant","Chartered accountant"],["advisor","Financial advisor"],["family","Family"],["other","Other"]],
    doc:[["will","Will"],["registered-will","Registered will (sub-registrar)"],["poa-property","Power of attorney"],["living-will","Living will / advance directive"],["nomination","Nomination forms"],["marriage","Marriage certificate"],["deed","Property sale deed"],["tax","ITR acknowledgements"],["other","Other"]],
    acct:[["bank","Savings account or FD"],["demat","Demat (shares)"],["mf","Mutual funds"],["ppf","PPF"],["epf","EPF / VPF"],["nps","NPS"],["ssy","Sukanya Samriddhi"],["pension","Pension"],["locker","Bank locker"],["crypto","Crypto"],["other","Other"]],
    ins:[["life","Life (LIC or private)"],["term","Term insurance"],["group-life","Life, through work"],["health","Health"],["critical","Critical illness"],["home","Home"],["auto","Car or two-wheeler"],["other","Other"]]}
};
function kinds(list,c){return (KINDS_BY[c]&&KINDS_BY[c][list])||KINDS[list]||[];}
/* Each section: key, title, singular, fields [key, label, type, options|hint]. Types: t text, a long text, s select, d date, l last 4 digits, p phone, e email. */
var SECTIONS=[
  {k:"people",t:"People",one:"person",blurb:"Executor, powers of attorney, guardians, your lawyer: who does what, and how to reach them.",
    f:[["role","Role","s","role"],["name","Name","t"],["phone","Phone","p"],["email","Email","e"],["note","Note","a"]],title:"name",sub:"role"},
  {k:"docs",t:"Will & documents",one:"document",blurb:"Where the originals are. The original will matters most: a copy usually isn't enough.",
    f:[["kind","What","s","doc"],["where","Where the original is","t","Lawyer's office, fire safe at home, safety deposit box…"],["date","Signed or last updated","d"],["who","Prepared by","t"],["note","Note","a"]],title:"kind",sub:"where"},
  {k:"insurance",t:"Insurance",one:"policy",blurb:"Policies and who they pay. Only the last 4 digits of a policy number.",
    f:[["kind","Type","s","ins"],["insurer","Insurer","t"],["last4","Policy number, last 4","l"],["amount","Coverage","t","Amount"],["benef","Beneficiaries","t","Name (share)"],["contact","Claims contact","t"],["where","Where the papers are","t"],["note","Note","a"]],title:"insurer",sub:"kind"},
  {k:"accounts",t:"Accounts & pensions",one:"account",blurb:"Where money is. Last 4 digits only, never full numbers or logins.",
    f:[["kind","Type","s","acct"],["inst","Bank or institution","t"],["last4","Account number, last 4","l"],["benef","Named beneficiary","t","None, or name"],["note","Note","a"]],title:"inst",sub:"kind"},
  {k:"property",t:"Property & valuables",one:"item",blurb:"Home, car, safety deposit box, jewellery, anything with a key or a deed.",
    f:[["what","What","t"],["where","Where it is / where the key is","t"],["note","Note","a"]],title:"what",sub:"where"},
  {k:"bills",t:"Bills & debts",one:"item",blurb:"What needs paying or cancelling: mortgage, loans, cards, phone, subscriptions.",
    f:[["what","What","t"],["who","With","t"],["note","What to do","a"]],title:"what",sub:"who"},
  {k:"digital",t:"Digital life",one:"item",blurb:"How to get into accounts without writing passwords here: for example, where your password manager's emergency kit is.",
    f:[["what","Account or device","t"],["how","How someone gets in, or what to do with it","a"]],title:"what",sub:"how"},
  {k:"letters",t:"Letters",one:"letter",blurb:"Words for the people you love. Only those with access to the file can read them.",
    f:[["to","To","t"],["text","Letter","a"]],title:"to",sub:""}
];
var LIM={t:200,a:4000,s:40,d:10,l:4,p:40,e:120};
function str(v,n){return String(v==null?"":v).slice(0,n);}
function kindLabel(list,v,c){
  var tries=[kinds(list,c),KINDS[list]||[]];Object.keys(KINDS_BY).forEach(function(k){tries.push(KINDS_BY[k][list]||[]);});
  for(var i=0;i<tries.length;i++){var x=tries[i].filter(function(k){return k[0]===v;})[0];if(x)return x[1];}return "";
}
function clean(s){
  s=s&&typeof s==="object"?s:{};
  var o={ts:+s.ts||0,me:{name:str(s.me&&s.me.name,60)},items:{},wishes:str(s.wishes,6000),reviewed:/^\d{4}-\d{2}-\d{2}$/.test(s.reviewed)?s.reviewed:"",
    grants:{},invites:{},keys:null,card:{note:str(s.card&&s.card.note,160),c1:str(s.card&&s.card.c1,24),c2:str(s.card&&s.card.c2,24)},ticks:{}};
  if(s.ticks&&typeof s.ticks==="object")Object.keys(s.ticks).slice(0,20).forEach(function(g){var t=s.ticks[g];if(t&&typeof t==="object"){o.ticks[g]={};Object.keys(t).slice(0,40).forEach(function(k){if(t[k])o.ticks[g][k]=1;});}});
  SECTIONS.forEach(function(sec){
    o.items[sec.k]=(s.items&&Array.isArray(s.items[sec.k])?s.items[sec.k]:[]).slice(0,200).filter(function(x){return x&&x.id;}).map(function(x){
      var y={id:str(x.id,24)};sec.f.forEach(function(f){y[f[0]]=f[2]==="l"?last4(x[f[0]]):str(x[f[0]],LIM[f[2]]);});return y;});
  });
  if(s.grants&&typeof s.grants==="object")Object.keys(s.grants).slice(0,20).forEach(function(g){var k=s.grants[g]&&s.grants[g].k;if(typeof k==="string"&&k.length<80)o.grants[g]={k:k};});
  if(s.invites&&typeof s.invites==="object")Object.keys(s.invites).slice(0,20).forEach(function(g){if(typeof s.invites[g]==="string"&&s.invites[g].length<80)o.invites[g]=s.invites[g];});
  if(s.keys&&s.keys.priv&&s.keys.pub)o.keys={priv:s.keys.priv,pub:String(s.keys.pub).slice(0,600)};
  return o;
}
/* Keep only the last 4 digits, whatever was typed. */
function last4(v){var d=String(v==null?"":v).replace(/\D/g,"");return d.slice(-4);}
/* Things that look like secrets: long digit runs (card, account, SIN numbers) or passwords. Phone and date fields are exempt. */
function risky(text){
  text=String(text||"");
  if(/(?:\d[\s-]?){8,}/.test(text.replace(/\(\d{3}\)\s?\d{3}-\d{4}|\+?1?[\s-]?\d{3}[\s-]\d{3}[\s-]\d{4}|\+91[\s-]?\d{5}[\s-]?\d{5}/g,"")))return "That looks like a full account, card or ID number (SIN, SSN, Aadhaar or PAN). Keep only the last 4 digits here.";
  if(/\b(password|passcode|pin|pwd)\s*[:=]/i.test(text))return "Don't write passwords or PINs here. Say where to find them instead, like a password manager's emergency kit.";
  return "";
}
function count(s){var n=0;SECTIONS.forEach(function(sec){n+=(s.items[sec.k]||[]).length;});return n+(s.wishes?1:0);}
/* What a trusted person receives: the file only, never keys or invites. */
function shareable(s){return {v:1,me:s.me,items:s.items,wishes:s.wishes,reviewed:s.reviewed,ts:s.ts,country:s.country||""};}
/* What a well-kept file has. Each: [key, label, done?, what to add]. */
function checklist(s,today,hasTrusted,c){
  var it=s.items,has=function(sec,f){return (it[sec]||[]).some(f||function(){return true;});};
  return [
    ["will","Where your original will is",has("docs",function(x){return x.kind==="will"&&x.where;}),"docs"],
    ["executor","Who your executor is",has("people",function(x){return x.role==="executor";}),"people"],
    ["poa",c==="US"?"Power of attorney and health care proxy":c==="IN"?"Power of attorney and nominations":"Powers of attorney (property and personal care)",has("docs",function(x){return x.kind==="poa-property";})&&has("docs",function(x){return x.kind==="poa-care";})||has("people",function(x){return x.role==="poa-property";})&&has("people",function(x){return x.role==="poa-care";}),"docs"],
    ["insurance","Insurance and who it pays",has("insurance",function(x){return x.benef;}),"insurance"],
    ["accounts",c==="US"?"Bank accounts, retirement plans and pensions":c==="IN"?"Bank accounts, PPF, EPF, demat and pensions":"Bank accounts, registered plans and pensions",has("accounts"),"accounts"],
    ["bills","Bills and debts to settle or cancel",has("bills"),"bills"],
    ["digital","How to get into phones and online accounts",has("digital"),"digital"],
    ["wishes","Your wishes",!!s.wishes,"wishes"],
    ["trusted","A trusted person who can open it",!!hasTrusted,"trust"],
    ["reviewed","Reviewed in the last year",!reviewDue(s,today),"review"]
  ];
}
/* First steps for whoever settles things, by country. General information from public sources, not legal advice. */
var STEPS={
  CA:{where:"Ontario",steps:[
  ["will","Find the original will. A copy usually isn't enough for probate."],
  ["certs","Get several copies of the death certificate or the funeral director's statement of death."],
  ["funeral","Arrange the funeral or memorial, following the wishes in this file."],
  ["canada","Tell the federal government (Service Canada, 1-800-277-9914): CPP, OAS, the Social Insurance Number and benefits. Search \"what to do when someone dies\" on canada.ca."],
  ["ontario","Cancel the health card, driver's licence and other Ontario IDs. ontario.ca/death has the steps."],
  ["insurers","Call each insurer in this file to start the claims."],
  ["banks","Tell the banks and investment firms. Ask what they need to release or transfer accounts."],
  ["bills","Cancel or settle the bills and subscriptions listed here."],
  ["probate","Ask a lawyer whether probate (a Certificate of Appointment of Estate Trustee) is needed."],
  ["eir","If there's probate in Ontario, file the Estate Information Return within 90 days of the certificate."],
  ["tax","File the final tax return (and an estate T3 if needed) and ask the CRA for a clearance certificate before giving out everything."]]},
  US:{where:"the US",steps:[
  ["will","Find the original will and any living trust. The original will usually has to be filed with the probate court."],
  ["certs","Get certified copies of the death certificate, often 10 or more. The funeral home can order them."],
  ["funeral","Arrange the funeral or memorial, following the wishes in this file."],
  ["ssa","Tell Social Security (1-800-772-1213); the funeral home often reports it. Ask about survivor benefits. Return any payment for the month of death."],
  ["credit","Ask Equifax, Experian and TransUnion to flag the credit file as deceased, to stop identity theft."],
  ["ids","Cancel the driver's license with the state, and passport, voter registration and memberships."],
  ["insurers","Call each insurer and employer benefits office in this file to start the claims."],
  ["banks","Tell the banks, brokerages and retirement plans. Accounts with a named beneficiary (POD/TOD, 401(k), IRA) usually pass outside the will."],
  ["probate","Ask a probate lawyer or the county probate court whether probate is needed. Each state has its own rules and a simpler path for small estates."],
  ["ein","If the estate earns income, get an EIN for it from the IRS and open an estate account."],
  ["tax","File the final federal and state income tax returns by the next tax day, and Form 1041 if the estate has $600 or more of income."]]},
  IN:{where:"India",steps:[
  ["will","Find the will, if there is one. Without a will, succession law decides who inherits; a lawyer can explain which law applies."],
  ["certs","Make sure the death is registered with the municipal or panchayat registrar (within 21 days; hospitals usually do it) and get several copies of the death certificate."],
  ["funeral","Arrange the last rites, following the wishes in this file."],
  ["heir","Apply for a legal heir certificate (tehsildar or revenue office). Where there's no nominee, banks or companies may ask for a succession certificate from a civil court."],
  ["banks","Visit each bank with the death certificate. Nominees can claim accounts and fixed deposits with the bank's claim form; open the locker with the bank present."],
  ["epf","Claim EPF and pension through EPFO with the employer (Form 20, 10D and 5IF for EDLI insurance)."],
  ["invest","Ask the depository participant (for demat) and each mutual fund house to transmit holdings to the nominee or legal heirs."],
  ["insurers","Call each insurer in this file (LIC, term and health) to start the claims."],
  ["property","Update property records (mutation in the land or municipal records) with the death certificate and will or heir certificate."],
  ["bills","Cancel or transfer bills, subscriptions, SIMs and utilities listed here."],
  ["tax","Register as legal heir on the income tax e-filing portal and file the final ITR. Surrender the PAN after that."]]}
};
function firstSteps(c){return (STEPS[c]||STEPS.CA).steps;}
function stepsWhere(c){return (STEPS[c]||STEPS.CA).where;}
var FIRST_STEPS=STEPS.CA.steps;
function daysBetween(a,b){return Math.round((Date.parse(b+"T12:00:00")-Date.parse(a+"T12:00:00"))/864e5);}
/* A file gets stale: a reminder once a year. */
function reviewDue(s,today){return !s.reviewed||daysBetween(s.reviewed,today)>=365;}
var api={kinds:kinds,firstSteps:firstSteps,stepsWhere:stepsWhere,checklist:checklist,FIRST_STEPS:FIRST_STEPS,KINDS:KINDS,SECTIONS:SECTIONS,clean:clean,last4:last4,risky:risky,count:count,shareable:shareable,kindLabel:kindLabel,reviewDue:reviewDue,daysBetween:daysBetween};
if(typeof module!=="undefined"&&module.exports)module.exports=api;else root.LegacyCore=api;
})(typeof self!=="undefined"?self:this);
