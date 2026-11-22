/* Legacy core: what the file holds, cleaning, and the checks that keep secrets out of it. No DOM, no network. */
(function(root){
"use strict";
var KINDS={
  role:[["executor","Executor"],["alt-executor","Backup executor"],["poa-property","Power of attorney, property"],["poa-care","Power of attorney, personal care"],["guardian","Guardian for children"],["lawyer","Lawyer"],["accountant","Accountant"],["advisor","Financial advisor"],["family","Family"],["other","Other"]],
  doc:[["will","Will"],["poa-property","Power of attorney, property"],["poa-care","Power of attorney, personal care"],["living-will","Living will / care wishes"],["trust","Trust"],["marriage","Marriage or separation papers"],["deed","Property deed"],["tax","Tax returns"],["other","Other"]],
  ins:[["life","Life"],["group-life","Life, through work"],["disability","Disability"],["critical","Critical illness"],["mortgage","Mortgage"],["home","Home or tenant"],["auto","Car"],["travel","Travel"],["other","Other"]],
  acct:[["bank","Chequing or savings"],["tfsa","TFSA"],["rrsp","RRSP or RRIF"],["fhsa","FHSA"],["resp","RESP"],["pension","Work pension"],["gov","CPP / OAS"],["nonreg","Non-registered"],["crypto","Crypto"],["other","Other"]]
};
/* Each section: key, title, singular, fields [key, label, type, options|hint]. Types: t text, a long text, s select, d date, l last 4 digits, p phone, e email. */
var SECTIONS=[
  {k:"people",t:"People",one:"person",blurb:"Executor, powers of attorney, guardians, your lawyer: who does what, and how to reach them.",
    f:[["role","Role","s","role"],["name","Name","t"],["phone","Phone","p"],["email","Email","e"],["note","Note","a"]],title:"name",sub:"role"},
  {k:"docs",t:"Will & documents",one:"document",blurb:"Where the originals are. The original will matters most: a copy usually isn't enough.",
    f:[["kind","What","s","doc"],["where","Where the original is","t","Lawyer's office, fire safe at home, safety deposit box…"],["date","Signed or last updated","d"],["who","Prepared by","t"],["note","Note","a"]],title:"kind",sub:"where"},
  {k:"insurance",t:"Insurance",one:"policy",blurb:"Policies and who they pay. Only the last 4 digits of a policy number.",
    f:[["kind","Type","s","ins"],["insurer","Insurer","t"],["last4","Policy number, last 4","l"],["amount","Coverage","t","$500,000"],["benef","Beneficiaries","t","Name (share)"],["contact","Claims contact","t"],["where","Where the papers are","t"],["note","Note","a"]],title:"insurer",sub:"kind"},
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
function kindLabel(list,v){var x=(KINDS[list]||[]).filter(function(k){return k[0]===v;})[0];return x?x[1]:"";}
function clean(s){
  s=s&&typeof s==="object"?s:{};
  var o={ts:+s.ts||0,me:{name:str(s.me&&s.me.name,60)},items:{},wishes:str(s.wishes,6000),reviewed:/^\d{4}-\d{2}-\d{2}$/.test(s.reviewed)?s.reviewed:"",
    grants:{},invites:{},keys:null};
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
  if(/(?:\d[\s-]?){8,}/.test(text.replace(/\(\d{3}\)\s?\d{3}-\d{4}|\+?1?[\s-]?\d{3}[\s-]\d{3}[\s-]\d{4}/g,"")))return "That looks like a full account, card or SIN number. Keep only the last 4 digits here.";
  if(/\b(password|passcode|pin|pwd)\s*[:=]/i.test(text))return "Don't write passwords or PINs here. Say where to find them instead, like a password manager's emergency kit.";
  return "";
}
function count(s){var n=0;SECTIONS.forEach(function(sec){n+=(s.items[sec.k]||[]).length;});return n+(s.wishes?1:0);}
/* What a trusted person receives: the file only, never keys or invites. */
function shareable(s){return {v:1,me:s.me,items:s.items,wishes:s.wishes,reviewed:s.reviewed,ts:s.ts};}
function daysBetween(a,b){return Math.round((Date.parse(b+"T12:00:00")-Date.parse(a+"T12:00:00"))/864e5);}
/* A file gets stale: a reminder once a year. */
function reviewDue(s,today){return !s.reviewed||daysBetween(s.reviewed,today)>=365;}
var api={KINDS:KINDS,SECTIONS:SECTIONS,clean:clean,last4:last4,risky:risky,count:count,shareable:shareable,kindLabel:kindLabel,reviewDue:reviewDue,daysBetween:daysBetween};
if(typeof module!=="undefined"&&module.exports)module.exports=api;else root.LegacyCore=api;
})(typeof self!=="undefined"?self:this);
