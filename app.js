"use strict";
/* Legacy: where your will and papers are, who does what, insurance and beneficiaries, and letters,
   with a trusted person who can open it after a waiting period you can cancel.
   Storage, sign-in, the Pixora passcode and encrypted sync come from pixora-kit.js. The copy a trusted
   person can open is encrypted on this phone with a key only their phone can unwrap; the server only
   decides when they may fetch it (see legacyGrants in firestore.rules). */
var L=LegacyCore,K=PixoraKit,esc=K.esc;
var S=null,tab="file",mine=[],shared=[],unsubs=[],viewing=null,joinReq=null,copyT=null,copied={};
var enc=new TextEncoder(),dec=new TextDecoder(),sub=crypto.subtle;
function $(s){return document.querySelector(s);}
function z(n){return String(n).padStart(2,"0");}
function iso(d){d=d||new Date();return d.getFullYear()+"-"+z(d.getMonth()+1)+"-"+z(d.getDate());}
function nice(ms){return new Date(ms).toLocaleDateString(window.PixoraCountry?PixoraCountry.locale():"en-CA",{weekday:"short",month:"short",day:"numeric",year:"numeric"});}
function niceIso(s){return s?nice(Date.parse(s+"T12:00:00")):"";}
var tt=null;function toast(m){var t=$("#toast");t.textContent=m;t.hidden=false;clearTimeout(tt);tt=setTimeout(function(){t.hidden=true;},4000);}
function rnd(n){return crypto.getRandomValues(new Uint8Array(n));}
function b64(u){var s="";for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s);}
function unb64(s){var b=atob(s),o=new Uint8Array(b.length);for(var i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
function b64url(u){return b64(u).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function CC(){return (S&&S.country)||(window.PixoraCountry?PixoraCountry.get():"CA");}
function sel(list,v){var ks=L.kinds(list,CC()).slice();if(v&&!ks.some(function(k){return k[0]===v;})&&L.kindLabel(list,v))ks.push([v,L.kindLabel(list,v)]);return ks.map(function(k){return '<option value="'+k[0]+'"'+(k[0]===v?" selected":"")+'>'+esc(k[1])+'</option>';}).join("");}
function save(){K.save(S);queueCopies();}

/* ---------- crypto for the trusted person's copy ---------- */
async function sha256hex(s){var h=new Uint8Array(await sub.digest("SHA-256",enc.encode(s)));return Array.prototype.map.call(h,function(x){return z(x.toString(16));}).join("");}
async function ensureKeys(){
  if(S.keys)return;
  var kp=await sub.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
  var priv=await sub.exportKey("jwk",kp.privateKey),pub=await sub.exportKey("jwk",kp.publicKey);
  S.keys={priv:priv,pub:JSON.stringify({kty:pub.kty,crv:pub.crv,x:pub.x,y:pub.y})};K.save(S);
}
function importPub(s){return sub.importKey("jwk",JSON.parse(s),{name:"ECDH",namedCurve:"P-256"},false,[]);}
async function wrapAes(bits){var base=await sub.importKey("raw",bits,"HKDF",false,["deriveKey"]);
  return sub.deriveKey({name:"HKDF",hash:"SHA-256",salt:enc.encode("pixora-legacy"),info:enc.encode("legacy-wrap-v1")},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);}
/* Seal the file key to the trusted person's public key (fresh one-time key each time). */
async function wrapKey(pubStr,raw){
  var eph=await sub.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
  var bits=await sub.deriveBits({name:"ECDH",public:await importPub(pubStr)},eph.privateKey,256);
  var k=await wrapAes(bits),iv=rnd(12),ct=new Uint8Array(await sub.encrypt({name:"AES-GCM",iv:iv},k,raw));
  var ep=await sub.exportKey("jwk",eph.publicKey);
  return {epk:JSON.stringify({kty:ep.kty,crv:ep.crv,x:ep.x,y:ep.y}),iv:b64(iv),ct:b64(ct)};
}
async function unwrapKey(wk){
  var priv=await sub.importKey("jwk",S.keys.priv,{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
  var bits=await sub.deriveBits({name:"ECDH",public:await importPub(wk.epk)},priv,256);
  return new Uint8Array(await sub.decrypt({name:"AES-GCM",iv:unb64(wk.iv)},await wrapAes(bits),unb64(wk.ct)));
}
async function aes(raw){return sub.importKey("raw",raw,"AES-GCM",false,["encrypt","decrypt"]);}
async function sealCopy(raw,obj){var iv=rnd(12);return {iv:b64(iv),ct:b64(new Uint8Array(await sub.encrypt({name:"AES-GCM",iv:iv},await aes(raw),enc.encode(JSON.stringify(obj)))))};}
async function openCopy(raw,box){return JSON.parse(dec.decode(await sub.decrypt({name:"AES-GCM",iv:unb64(box.iv)},await aes(raw),unb64(box.ct))));}
/* A 6-digit code both phones show, so the owner knows the key really came from the person they invited. */
async function safety(pub){var h=new Uint8Array(await sub.digest("SHA-256",enc.encode(pub)));var n=((h[0]<<16)|(h[1]<<8)|h[2])%1000000;var s=String(n).padStart(6,"0");return s.slice(0,3)+" "+s.slice(3);}

/* ---------- the server side of trusted access ---------- */
function G(id){return K.db.collection("legacyGrants").doc(id);}
function reqMs(g){return g.reqAt&&g.reqAt.toMillis?g.reqAt.toMillis():Date.now();}
function opensAt(g){return reqMs(g)+g.wait*864e5;}
function canOpen(g){return g.status==="released"||(g.status==="requested"&&Date.now()>=opensAt(g));}
function listen(){
  unsubs.forEach(function(u){u();});unsubs=[];
  if(K.local||!K.db)return;
  var col=K.db.collection("legacyGrants");
  unsubs.push(col.where("owner","==",K.uid).onSnapshot(function(q){mine=q.docs.map(function(d){var x=d.data();x.id=d.id;return x;});queueCopies();rerender();},function(){}));
  unsubs.push(col.where("trustee","==",K.uid).onSnapshot(function(q){shared=q.docs.map(function(d){var x=d.data();x.id=d.id;return x;});rerender();},function(){}));
}
function rerender(){if(!$("#dlg").open&&!viewing)render();}
/* Keep each trusted person's encrypted copy current, a moment after edits. */
function queueCopies(){clearTimeout(copyT);copyT=setTimeout(writeCopies,1500);}
async function writeCopies(){
  if(K.local||!K.db)return;
  for(var i=0;i<mine.length;i++){
    var g=mine[i],k=S.grants[g.id];
    if(!k||["active","requested","released"].indexOf(g.status)<0||copied[g.id]===S.ts)continue;
    try{var box=await sealCopy(unb64(k.k),L.shareable(S));await G(g.id).collection("copy").doc("data").set({iv:box.iv,ct:box.ct,ts:S.ts});copied[g.id]=S.ts;}catch(e){}
  }
}

/* ---------- screens ---------- */
function header(eb,title){
  return '<header class="top"><div><p class="eyebrow">'+esc(eb)+'</p><h1>'+esc(title)+'</h1></div><div class="row"><button class="btn q s" data-act="settings">Settings</button></div></header>'+
    '<button class="status noprint" id="st" data-act="settings">'+esc(K.status())+'</button>';
}
function render(){
  var app=$("#app");app.hidden=false;$("#tabs").hidden=!!viewing;
  document.querySelectorAll("#tabs button").forEach(function(b){b.setAttribute("aria-current",b.dataset.tab===tab?"page":"false");});
  app.innerHTML=viewing?readView(viewing.data,viewing.who):tab==="file"?fileView():tab==="trust"?trustView():settingsView();
  fillCodes();
}
function alerts(){
  return mine.filter(function(g){return g.status==="requested";}).map(function(g){
    return '<section class="alert" role="alert"><p><b>'+esc(g.trusteeName||"Your trusted person")+' asked to open your Legacy file</b> on '+esc(nice(reqMs(g)))+'.</p>'+
      '<p>'+(Date.now()>=opensAt(g)?"The waiting period is over, so they can open it now.":"It opens to them on "+esc(nice(opensAt(g)))+" unless you deny it.")+' If you didn\'t expect this, deny it.</p>'+
      '<div class="row"><button class="btn p s" data-act="deny" data-id="'+g.id+'">Deny</button><button class="btn s" data-act="release" data-id="'+g.id+'">Let them open it now</button></div></section>';
  }).join("");
}
function entryLine(sec,x){
  var f=sec.f.filter(function(f){return f[0]===sec.title;})[0],t=f&&f[2]==="s"?L.kindLabel(f[3],x[sec.title]):x[sec.title];
  var sf=sec.f.filter(function(f){return f[0]===sec.sub;})[0],s=sf?(sf[2]==="s"?L.kindLabel(sf[3],x[sec.sub]):x[sec.sub]):"";
  if(sec.k==="docs")t=L.kindLabel("doc",x.kind)||"Document";
  if(sec.k==="insurance"&&x.amount)s=(s?s+" · ":"")+x.amount;
  if(x.last4)s=(s?s+" · ":"")+"ending "+x.last4;
  return '<button class="ent" data-act="edit" data-s="'+sec.k+'" data-id="'+x.id+'"><b>'+esc(t||"(untitled)")+'</b>'+(s?'<span>'+esc(String(s).slice(0,140))+'</span>':"")+'</button>';
}
function fileView(){
  var h=header("Legacy","My file")+alerts(),n=L.count(S),due=L.reviewDue(S,iso());
  if(!n)h+='<section class="card"><h2>What this is for</h2><p>If something happened to you, the people you trust would need to know where your will is, who your executor is, what insurance you have and who it pays, and what needs cancelling. This keeps all of that in one place, with a trusted person who can open it after a waiting period you can stop.</p>'+
    '<p class="note">Never write full account numbers, card numbers, ID numbers (SIN, SSN, Aadhaar) or passwords here. Write where to find things instead. This doesn\'t replace a will.</p></section>';
  h+='<section class="card"><div class="secthead"><h2>'+(S.me.name?esc(S.me.name)+"’s file":"Your file")+'</h2><button class="add noprint" data-act="me">'+(S.me.name?"Change name":"Add your name")+'</button></div>'+
    '<p class="note">'+(S.reviewed?"Last reviewed "+esc(niceIso(S.reviewed)):"Not reviewed yet")+(due&&n?'. Worth a look once a year, and after a move, marriage, birth or new policy.':"")+'</p>'+
    '<div class="row noprint">'+(n?'<button class="btn q s" data-act="reviewed">Mark reviewed today</button><button class="btn q s" data-act="preview">See what they\'d see</button>':"")+'<button class="btn q s" data-act="print">Print</button><button class="btn q s" data-act="wallet">Wallet card</button></div></section>';
  h+=checkCard();
  L.SECTIONS.forEach(function(sec){
    var list=S.items[sec.k]||[];
    h+='<section class="card"><div class="secthead"><h2>'+esc(sec.t)+'</h2><button class="add noprint" data-act="new" data-s="'+sec.k+'">+ Add '+esc(sec.one)+'</button></div>'+(list.length?"":'<p class="note">'+esc(sec.blurb)+'</p>')+list.map(function(x){return entryLine(sec,x);}).join("")+'</section>';
  });
  h+='<section class="card"><div class="secthead"><h2>Wishes</h2><button class="add noprint" data-act="wishes">'+(S.wishes?"Edit":"+ Add")+'</button></div>'+
    (S.wishes?'<p style="white-space:pre-wrap">'+esc(S.wishes.slice(0,600))+(S.wishes.length>600?"…":"")+'</p>':'<p class="note">Funeral or memorial, organ donation, who takes the pets, anything else.</p>')+'</section>';
  return h+'<p class="note">Encrypted on this phone before it syncs. Pixora, the server and any AI can\'t read it. A trusted person can only open it the way you set up under Trusted people.</p>';
}
/* How complete the file is, with a button for each missing piece. */
function checkCard(){
  var trusted=mine.some(function(g){return ["active","requested","released"].indexOf(g.status)>=0;});
  var c=L.checklist(S,iso(),trusted,CC()),done=c.filter(function(x){return x[2];}).length;
  if(done===c.length)return '<section class="card noprint"><p class="small"><b>All '+c.length+' parts are filled in.</b> Look it over once a year.</p></section>';
  var h='<section class="card noprint"><div class="secthead"><h2>'+done+' of '+c.length+' done</h2></div><div class="bar" style="height:8px;border-radius:4px;background:var(--line);overflow:hidden"><i style="display:block;height:100%;width:'+Math.round(100*done/c.length)+'%;background:var(--accent)"></i></div>';
  c.filter(function(x){return !x[2];}).slice(0,5).forEach(function(x){
    var act=x[3]==="wishes"?'data-act="wishes"':x[3]==="trust"?'data-act="tab" data-t="trust"':x[3]==="review"?'data-act="reviewed"':'data-act="new" data-s="'+x[3]+'"';
    h+='<button class="ent" '+act+'><b>'+esc(x[1])+'</b><span>Add it</span></button>';
  });
  return h+'</section>';
}
/* A wallet-size card: who to call, and where the file is. */
function walletDialog(){
  var ppl=(S.items.people||[]).filter(function(p){return p.phone;});
  var opt=function(sel){return '<option value="">None</option>'+ppl.map(function(p){return '<option value="'+esc(p.id)+'"'+(p.id===sel?" selected":"")+'>'+esc(p.name)+' · '+esc(L.kindLabel("role",p.role))+'</option>';}).join("");};
  dlg('<h2>Wallet card</h2><p class="small muted">A card to keep in your wallet: who to call in an emergency, and that your details are in Legacy. Print it, cut it out, fold it in half.</p>'+
    (ppl.length?'<label class="f">First contact<select id="w-c1">'+opt(S.card.c1||(ppl[0]&&ppl[0].id))+'</select></label><label class="f">Second contact<select id="w-c2">'+opt(S.card.c2)+'</select></label>':'<p class="small">Add people with phone numbers under People first.</p>')+
    '<label class="f">Note (optional)<input type="text" id="w-note" maxlength="160" value="'+esc(S.card.note)+'" placeholder="Organ donor. Allergic to penicillin."></label>'+
    '<div class="row"><button class="btn p" data-act="printwallet">Print the card</button><button class="btn q" data-act="close">Close</button></div>');
}
function printWallet(){
  var byId=function(id){return (S.items.people||[]).filter(function(p){return p.id===id;})[0];},c1=byId(S.card.c1),c2=byId(S.card.c2),tr=mine.filter(function(g){return g.status!=="invited"&&g.trusteeName;})[0];
  var line=function(p){return p?'<p><b>'+esc(p.name)+'</b> · '+esc(L.kindLabel("role",p.role))+'<br>'+esc(p.phone)+'</p>':"";};
  var el=$("#walletcard")||document.body.appendChild(Object.assign(document.createElement("div"),{id:"walletcard"}));
  el.innerHTML='<div class="wc"><div class="wcf"><p class="wct">In an emergency, please call</p>'+line(c1)+line(c2)+(S.card.note?'<p class="wcn">'+esc(S.card.note)+'</p>':"")+'</div>'+
    '<div class="wcf"><p class="wct">'+esc(S.me.name||"")+'</p><p>My will, insurance and wishes are recorded in Pixora Legacy.'+(tr?' '+esc(tr.trusteeName)+' can open them.':"")+'</p><p class="wcs">spoolsync.github.io/legacy</p></div></div>';
  document.body.classList.add("printcard");var off=function(){document.body.classList.remove("printcard");window.removeEventListener("afterprint",off);};window.addEventListener("afterprint",off);
  setTimeout(function(){window.print();setTimeout(off,1500);},50);K.track("wallet_print");
}
function statusPill(g){
  var m={invited:["Invite sent",""],accepted:["Needs your OK","bad"],active:["Set up","on"],requested:["Asked to open","bad"],released:["Can open now","on"]}[g.status]||[g.status,""];
  return '<span class="pill '+m[1]+'">'+esc(m[0])+'</span>';
}
function trustView(){
  var h=header("Legacy","Trusted people")+alerts();
  if(K.local)return h+'<section class="card"><p>Trusted people need a Pixora account on both sides, so the encrypted copy has somewhere to live.</p><div class="row"><button class="btn p" data-act="join">Sign in or create a Pixora account</button></div></section>';
  h+='<section class="card"><div class="secthead"><h2>People who can open my file</h2></div>'+
    '<p class="note">They can ask to open it at any time. You\'re told in every Pixora app and on Pixora Today, and you have the waiting period to say no. If you say nothing, they can open it when it ends.</p>';
  if(!mine.length)h+='<p class="note">Nobody yet.</p>';
  mine.forEach(function(g){
    h+='<div class="ent" style="cursor:default"><div class="secthead"><b>'+esc(g.trusteeName||"Invite")+'</b>'+statusPill(g)+'</div>';
    if(g.status==="invited")h+='<span>Waiting for them to open the invite link. Waiting period '+g.wait+' days.</span><div class="row"><button class="btn q s" data-act="link" data-id="'+g.id+'">Share the link again</button><button class="btn q s" data-act="remove" data-id="'+g.id+'">Cancel</button></div>';
    else if(g.status==="accepted")h+='<span>'+esc(g.trusteeEmail||"")+' accepted. Check that their screen shows the same code, then confirm.</span><p class="code" data-code="'+esc(g.pub||"")+'">··· ···</p><div class="row"><button class="btn p s" data-act="confirm" data-id="'+g.id+'">Codes match, confirm</button><button class="btn q s" data-act="remove" data-id="'+g.id+'">Remove</button></div>';
    else{
      h+='<span>'+esc(g.trusteeEmail||"")+' · waiting period '+g.wait+' day'+(g.wait===1?"":"s")+(g.status==="released"?" · you let them open it":"")+'</span><div class="row">';
      if(g.status==="active")h+='<button class="btn q s" data-act="wait" data-id="'+g.id+'">Change waiting period</button>';
      if(g.status==="released")h+='<button class="btn q s" data-act="takeback" data-id="'+g.id+'">Take back</button>';
      h+='<button class="btn q s" data-act="remove" data-id="'+g.id+'">Remove</button></div>';
    }
    h+='</div>';
  });
  h+='<div class="row"><button class="btn p s" data-act="invite">Add a trusted person</button></div></section>';
  h+='<section class="card"><h2>Files shared with me</h2>';
  if(!shared.length)h+='<p class="note">When someone makes you their trusted person, it shows here.</p>';
  shared.forEach(function(g){
    h+='<div class="ent" style="cursor:default"><div class="secthead"><b>'+esc(g.ownerName||"Someone")+'</b>'+statusPill(g)+'</div>';
    if(g.status==="accepted")h+='<span>Waiting for '+esc(g.ownerName)+' to confirm. Your code: </span><p class="code" data-code="'+esc(g.pub||"")+'">··· ···</p>';
    else if(g.status==="active")h+='<span>You can ask to open it. They\'re told and have '+g.wait+' day'+(g.wait===1?"":"s")+' to say no.</span><div class="row"><button class="btn s" data-act="ask" data-id="'+g.id+'">Ask to open it</button><button class="btn q s" data-act="leave" data-id="'+g.id+'">Step down</button></div>';
    else if(canOpen(g))h+='<div class="row"><button class="btn p s" data-act="open" data-id="'+g.id+'">Open '+esc(g.ownerName)+'’s file</button></div>';
    else if(g.status==="requested")h+='<span>You asked on '+esc(nice(reqMs(g)))+'. It opens on '+esc(nice(opensAt(g)))+' unless they say no.</span><div class="row"><button class="btn q s" data-act="withdraw" data-id="'+g.id+'">Withdraw the request</button>'+(g.ownerEmail?'<a class="btn q s" href="mailto:'+esc(g.ownerEmail)+'?subject='+encodeURIComponent("Legacy file")+'">Email them</a>':"")+'</div>';
    h+='</div>';
  });
  return h+'</section>';
}
function readView(d,who){
  var h='<div class="row noprint"><button class="btn q s" data-act="closeview">← Back</button><button class="btn q s" data-act="print">Print</button></div>'+
    '<header><p class="eyebrow">Legacy file'+(who?" · opened by you":" · preview")+'</p><h1>'+esc(d.me&&d.me.name?d.me.name:"Legacy file")+'</h1><p class="note">'+(d.reviewed?"Last reviewed "+esc(niceIso(d.reviewed)):"")+(d.ts?" · last changed "+esc(nice(d.ts)):"")+'</p></header>';
  L.SECTIONS.forEach(function(sec){
    var list=(d.items&&d.items[sec.k])||[];if(!list.length)return;
    h+='<section class="card read"><h2>'+esc(sec.t)+'</h2>';
    list.forEach(function(x){
      if(sec.k==="letters"){h+='<div class="kv" style="display:block"><p class="eyebrow">To '+esc(x.to)+'</p><p class="letter">'+esc(x.text)+'</p></div>';return;}
      h+='<dl class="kv">'+sec.f.map(function(f){var v=x[f[0]];if(!v)return "";if(f[2]==="s")v=L.kindLabel(f[3],v);if(f[2]==="l")v="ending "+v;if(f[2]==="d")v=niceIso(v);
        return '<dt>'+esc(f[1])+'</dt><dd>'+(f[2]==="p"?'<a href="tel:'+esc(String(v).replace(/[^\d+]/g,""))+'">'+esc(v)+'</a>':f[2]==="e"?'<a href="mailto:'+esc(v)+'">'+esc(v)+'</a>':esc(v))+'</dd>';}).join("")+'</dl>';
    });
    h+='</section>';
  });
  if(d.wishes)h+='<section class="card read"><h2>Wishes</h2><p style="white-space:pre-wrap">'+esc(d.wishes)+'</p></section>';
  /* The steps follow the file owner's country, not the reader's. */
  var oc=d.country||CC(),FS=L.firstSteps(oc);
  var tk=viewing&&viewing.gid?(S.ticks[viewing.gid]||{}):{},done=FS.filter(function(x){return tk[x[0]];}).length;
  h+='<section class="card read"><h2>First steps'+(who?" ("+done+" of "+FS.length+")":"")+'</h2><p class="note">For whoever settles things in '+esc(L.stepsWhere(oc))+'. General information, not legal advice; a lawyer can confirm what applies.'+(who?" Ticks are saved on your phone only.":"")+'</p>'+
    FS.map(function(x){return '<label class="chk" style="display:flex;gap:10px;align-items:flex-start;padding:6px 0;border-top:1px solid var(--line)"><input type="checkbox" data-act="tick" data-k="'+x[0]+'"'+(tk[x[0]]?" checked":"")+(who?"":" disabled")+'><span>'+esc(x[1])+'</span></label>';}).join("")+'</section>';
  return h;
}
function settingsView(){
  var h='<button class="btn q s" data-act="tab" data-t="file" style="align-self:flex-start">← Back</button><h1>Settings</h1>';
  if(window.PixoraCountry)h+=PixoraCountry.picker("Sets the first steps your family sees (Ontario, the US or India) and the account and document types here.");
  h+='<section class="card"><h2>Your copy</h2><p class="small muted">Download everything in Legacy as a file you keep, and bring it back here or on a new phone. It\'s a plain file, not encrypted, so keep it somewhere private, like a password manager or with your will. It doesn\'t include your trusted people.</p><div class="row"><button class="btn" data-act="export">Download a copy</button><label class="btn q" style="cursor:pointer">Restore from a copy<input type="file" id="restore" accept=".json,application/json" hidden></label></div></section>';
  h+='<section class="card"><h2>Ideas or problems?</h2><p class="small muted">Tell Sachin what would make Legacy better or what went wrong. Nothing from your data is sent.</p><div class="row"><button class="btn" data-act="feedback">Send feedback</button></div></section>';
  h+='<section class="card"><h2>Account</h2>'+(K.local?'<p class="small">On this phone only.</p><div class="row"><button class="btn" data-act="join">Sign in or create a Pixora account</button></div>':
    '<p class="small">Signed in as '+esc(K.email||"")+'. Your file is encrypted on this phone before it syncs. Nobody else can read it, not even Pixora.</p><div class="row"><button class="btn q" data-act="signout">Sign out</button></div>')+'</section>';
  h+='<section class="card"><h2>Delete my Legacy data</h2><p class="note">Deletes your file, removes your trusted people and their copies, and steps you down from files shared with you. Your Pixora login and other apps aren\'t affected. To delete the Pixora login itself, email pixora3dstudios@gmail.com.</p><div class="row"><button class="btn d" data-act="delall">Delete my Legacy data</button></div></section>';
  return h;
}
/* Fill in safety codes after render (they're computed). */
function fillCodes(){document.querySelectorAll("[data-code]").forEach(function(el){var p=el.dataset.code;if(p)safety(p).then(function(c){el.textContent=c;});});}

/* ---------- dialogs ---------- */
function dlg(html){var d=$("#dlg");d.innerHTML='<div class="form">'+html+'</div>';if(!d.open)d.showModal();return d;}
function closeDlg(){var d=$("#dlg");if(d.open)d.close();d.innerHTML="";render();fillCodes();}
$("#dlg").addEventListener("cancel",function(e){e.preventDefault();closeDlg();});
function secOf(k){return L.SECTIONS.filter(function(s){return s.k===k;})[0];}
function entryDialog(sk,id){
  var sec=secOf(sk),x=(S.items[sk]||[]).filter(function(i){return i.id===id;})[0],isNew=!x;x=x||{};
  var hint=sk==="digital"?'<p class="note">No passwords here. Say where they are, like "1Password emergency kit is in the fire safe".</p>':"";
  dlg('<h2>'+(isNew?"Add "+esc(sec.one):esc(sec.t))+'</h2>'+hint+sec.f.map(function(f){
    var v=x[f[0]]||"",inp;
    if(f[2]==="s")inp='<select id="e-'+f[0]+'">'+sel(f[3],v)+'</select>';
    else if(f[2]==="a")inp='<textarea id="e-'+f[0]+'" maxlength="4000"'+(sk==="letters"?' style="min-height:240px"':"")+'>'+esc(v)+'</textarea>';
    else if(f[2]==="d")inp='<input type="date" id="e-'+f[0]+'" value="'+esc(v)+'">';
    else inp='<input type="'+(f[2]==="e"?"email":f[2]==="p"?"tel":"text")+'" id="e-'+f[0]+'" value="'+esc(v)+'"'+(f[2]==="l"?' inputmode="numeric" placeholder="Last 4 digits"':' maxlength="200"')+(f[3]&&f[2]==="t"?' placeholder="'+esc(f[3])+'"':"")+'>';
    return '<label class="f">'+esc(f[1])+inp+'</label><p class="warn" id="w-'+f[0]+'" hidden></p>';
  }).join("")+'<div class="row"><button class="btn p" data-act="saveentry" data-s="'+sk+'" data-id="'+(x.id||"")+'">Save</button><button class="btn q" data-act="close">Cancel</button>'+(isNew?"":'<button class="btn d" data-act="delentry" data-s="'+sk+'" data-id="'+x.id+'">Delete</button>')+'</div>');
  sec.f.forEach(function(f){if(f[2]==="t"||f[2]==="a"){var el=$("#e-"+f[0]);el.addEventListener("input",function(){var w=L.risky(el.value),p=$("#w-"+f[0]);p.textContent=w;p.hidden=!w;});}});
}
async function inviteDialog(){
  dlg('<h2>Add a trusted person</h2><p class="note">They\'ll get a link. Once they accept on their phone and you both see the same code, they can ask to open your file. You\'re told, and they can open it only if you don\'t say no within the waiting period.</p>'+
    '<label class="f">Your name, as they\'ll see it<input type="text" id="v-me" maxlength="60" value="'+esc(S.me.name||"")+'"></label>'+
    '<label class="f">Waiting period<select id="v-wait"><option value="3">3 days</option><option value="7" selected>7 days</option><option value="14">14 days</option><option value="30">30 days</option></select></label>'+
    '<div class="row"><button class="btn p" data-act="mkinvite">Make the invite link</button><button class="btn q" data-act="close">Cancel</button></div>');
}
function linkFor(id){return location.origin+location.pathname+"#t="+id+"."+S.invites[id];}
function linkDialog(id){
  var url=linkFor(id);
  dlg('<h2>Send this link to them</h2><p class="note">Send it privately (a text or email to them only). Anyone with the link could accept, which is why you\'ll compare a code before anything is shared.</p>'+
    '<input type="text" readonly id="v-url" value="'+esc(url)+'"><div class="row">'+(navigator.share?'<button class="btn p" data-act="sharelink">Share…</button>':"")+'<button class="btn" data-act="copylink">Copy</button><button class="btn q" data-act="close">Done</button></div>');
}
async function joinFlow(gid,tok){
  if(K.local){dlg('<h2>You need a Pixora account</h2><p>To be someone\'s trusted person, sign in to a Pixora account. Then open the link again.</p><div class="row"><button class="btn p" data-act="join">Sign in</button><button class="btn q" data-act="close">Not now</button></div>');return;}
  var snap;try{snap=await G(gid).get();}catch(e){snap=null;}
  var g=snap&&snap.exists?snap.data():null;
  if(g&&g.trustee===K.uid){tab="trust";render();fillCodes();return;}
  if(!g||g.status!=="invited"){dlg('<h2>This invite can\'t be used</h2><p>It was already accepted, or it was cancelled. Ask them to send a new one.</p><div class="row"><button class="btn q" data-act="close">OK</button></div>');return;}
  if(g.owner===K.uid){dlg('<h2>That\'s your own invite</h2><p>Send it to the person you trust, so they open it on their phone.</p><div class="row"><button class="btn q" data-act="close">OK</button></div>');return;}
  joinReq={gid:gid,tok:tok,g:g};
  dlg('<h2>'+esc(g.ownerName)+' trusts you</h2><p>'+esc(g.ownerName)+' wants you to be able to open their Legacy file: where their will is, who to call, insurance and wishes.</p>'+
    '<p class="note">You can only open it after asking. They\'re told and have '+g.wait+' days to say no. Until then you see nothing.</p>'+
    '<label class="f">Your name, as they\'ll see it<input type="text" id="j-name" maxlength="60" value="'+esc(S.me.name||"")+'"></label>'+
    '<div class="row"><button class="btn p" data-act="accept">Accept</button><button class="btn q" data-act="close">Not now</button></div>');
}

/* ---------- events ---------- */
document.addEventListener("click",async function(e){
  var b=e.target.closest("[data-act]");if(!b||b.tagName==="SELECT"||(b.tagName==="INPUT"&&b.type!=="checkbox"))return;
  var a=b.dataset.act,id=b.dataset.id;
  try{
  if(a==="tab"){tab=b.dataset.t;render();}
  else if(a==="settings"){tab="settings";render();}
  else if(a==="close")closeDlg();
  else if(a==="new"||a==="edit")entryDialog(b.dataset.s,id);
  else if(a==="saveentry"){
    var sec=secOf(b.dataset.s),x={id:id||Date.now().toString(36)+Math.random().toString(36).slice(2,7)},any=false,risk="";
    sec.f.forEach(function(f){var v=$("#e-"+f[0]).value.trim();if(f[2]==="l")v=L.last4(v);x[f[0]]=v;if(v&&f[2]!=="s")any=true;if((f[2]==="t"||f[2]==="a")&&L.risky(v))risk=L.risky(v);});
    if(!any){toast("Fill in at least one thing.");return;}
    if(risk&&b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Save anyway";toast(risk);return;}
    var list=S.items[sec.k],i=list.findIndex(function(y){return y.id===x.id;});if(i>=0)list[i]=x;else{list.push(x);K.track("add_"+sec.k);}
    save();closeDlg();
  }
  else if(a==="delentry"){if(b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Tap again to delete";return;}S.items[b.dataset.s]=S.items[b.dataset.s].filter(function(y){return y.id!==id;});save();closeDlg();}
  else if(a==="me")dlg('<h2>Your name</h2><label class="f">Name<input type="text" id="m-name" maxlength="60" value="'+esc(S.me.name)+'"></label><div class="row"><button class="btn p" data-act="saveme">Save</button><button class="btn q" data-act="close">Cancel</button></div>');
  else if(a==="saveme"){S.me.name=$("#m-name").value.trim().slice(0,60);save();closeDlg();}
  else if(a==="wishes")dlg('<h2>Wishes</h2><p class="note">Funeral or memorial, organ donation, who takes the pets, anything else.</p><textarea id="w-text" maxlength="6000" style="min-height:260px">'+esc(S.wishes)+'</textarea><div class="row"><button class="btn p" data-act="savewish">Save</button><button class="btn q" data-act="close">Cancel</button></div>');
  else if(a==="savewish"){S.wishes=$("#w-text").value.slice(0,6000);save();closeDlg();K.track("wishes");}
  else if(a==="reviewed"){S.reviewed=iso();save();render();toast("Marked reviewed today.");K.track("reviewed");}
  else if(a==="print"){K.track("print");window.print();}
  else if(a==="wallet")walletDialog();
  else if(a==="printwallet"){if($("#w-c1"))S.card.c1=$("#w-c1").value;if($("#w-c2"))S.card.c2=$("#w-c2").value;S.card.note=$("#w-note").value.slice(0,160);save();closeDlg();printWallet();}
  else if(a==="tick"&&viewing&&viewing.gid){var tg=S.ticks[viewing.gid]=S.ticks[viewing.gid]||{};if(b.checked)tg[b.dataset.k]=1;else delete tg[b.dataset.k];K.save(S);K.track("first_step_tick");var h2=b.closest("section").querySelector("h2");if(h2)h2.textContent="First steps ("+Object.keys(tg).length+" of "+L.FIRST_STEPS.length+")";}
  else if(a==="preview"){viewing={data:L.shareable(S)};render();window.scrollTo(0,0);K.track("preview");}
  else if(a==="closeview"){viewing=null;render();fillCodes();}
  else if(a==="invite")inviteDialog();
  else if(a==="mkinvite"){
    var nm=$("#v-me").value.trim();if(!nm){toast("Add your name so they know who it's from.");return;}
    S.me.name=nm.slice(0,60);b.disabled=true;
    var ref=K.db.collection("legacyGrants").doc(),tok=b64url(rnd(18));
    await ref.set({owner:K.uid,ownerName:S.me.name,wait:+$("#v-wait").value,status:"invited",jh:await sha256hex(tok),created:Date.now()});
    S.invites[ref.id]=tok;save();K.track("invite");linkDialog(ref.id);
  }
  else if(a==="link")linkDialog(id);
  else if(a==="sharelink"){try{await navigator.share({title:"Legacy",text:"I'd like you to be my trusted person in Legacy.",url:$("#v-url").value});}catch(x){}}
  else if(a==="copylink"){try{await navigator.clipboard.writeText($("#v-url").value);toast("Copied.");}catch(x){$("#v-url").select();}}
  else if(a==="accept"){
    var j=joinReq,name=$("#j-name").value.trim();if(!name){toast("Add your name.");return;}
    b.disabled=true;await ensureKeys();if(!S.me.name){S.me.name=name.slice(0,60);save();}
    await G(j.gid).update({status:"accepted",trustee:K.uid,trusteeName:name.slice(0,60),trusteeEmail:K.email,pub:S.keys.pub,tok:j.tok});
    K.track("accept");var c=await safety(S.keys.pub);
    dlg('<h2>Accepted</h2><p>Tell '+esc(j.g.ownerName)+' this code, or check it matches what they see:</p><p class="code">'+c+'</p><p class="note">Once they confirm, it\'s listed under Trusted people. You can\'t see anything in their file unless you ask and the waiting period passes.</p><div class="row"><button class="btn p" data-act="close">OK</button></div>');
    tab="trust";joinReq=null;
  }
  else if(a==="confirm"){
    var g=mine.filter(function(x){return x.id===id;})[0];if(!g||!g.pub)return;b.disabled=true;
    var raw=rnd(32),wk=await wrapKey(g.pub,raw);S.grants[id]={k:b64(raw)};delete S.invites[id];K.save(S);
    await G(id).update({status:"active",wk:wk,ownerEmail:K.email||""});
    delete copied[id];await writeCopies();toast((g.trusteeName||"They")+" is set up.");K.track("confirm");
  }
  else if(a==="remove"){
    if(b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Tap again to remove";return;}
    await G(id).collection("copy").doc("data").delete().catch(function(){});await G(id).delete();
    delete S.grants[id];delete S.invites[id];save();K.track("remove_trusted");
  }
  else if(a==="wait")dlg('<h2>Waiting period</h2><select id="w-days">'+[1,3,7,14,30,60,90].map(function(d){var g=mine.filter(function(x){return x.id===id;})[0];return '<option value="'+d+'"'+(g&&g.wait===d?" selected":"")+'>'+d+' day'+(d===1?"":"s")+'</option>';}).join("")+'</select><div class="row"><button class="btn p" data-act="savewait" data-id="'+id+'">Save</button><button class="btn q" data-act="close">Cancel</button></div>');
  else if(a==="savewait"){await G(id).update({wait:+$("#w-days").value});closeDlg();}
  else if(a==="deny"){await G(id).update({status:"active",reqAt:null});toast("Denied. They can't open it.");K.track("deny");}
  else if(a==="release"){if(b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Tap again: they can open it now";return;}await G(id).update({status:"released",reqAt:null,relAt:Date.now()});K.track("release");}
  else if(a==="takeback"){await G(id).update({status:"active",reqAt:null});}
  else if(a==="ask"){
    if(b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Tap again: ask to open it";return;}
    await G(id).update({status:"requested",reqAt:firebase.firestore.FieldValue.serverTimestamp()});K.track("ask_open");
    var gg=shared.filter(function(x){return x.id===id;})[0];
    dlg('<h2>Asked</h2><p>'+esc(gg&&gg.ownerName||"They")+' will see it the next time they open a Pixora app. It opens to you after '+(gg?gg.wait:"the")+' days unless they say no.</p>'+
      (gg&&gg.ownerEmail?'<p class="note">You can also let them know directly.</p><div class="row"><a class="btn" href="mailto:'+esc(gg.ownerEmail)+'?subject='+encodeURIComponent("Legacy file")+'&body='+encodeURIComponent("I've asked to open your Legacy file in Pixora.")+'">Email them</a><button class="btn q" data-act="close">OK</button></div>':'<div class="row"><button class="btn q" data-act="close">OK</button></div>'));
  }
  else if(a==="withdraw"){await G(id).update({status:"active",reqAt:null});}
  else if(a==="leave"){if(b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Tap again to step down";return;}await G(id).delete();}
  else if(a==="open"){
    var sg=shared.filter(function(x){return x.id===id;})[0];b.disabled=true;
    try{var snap=await G(id).collection("copy").doc("data").get({source:"server"});if(!snap.exists)throw 0;
      var k=await unwrapKey(sg.wk),d=await openCopy(k,snap.data());viewing={data:d,who:true,gid:id};render();window.scrollTo(0,0);K.track("open_shared");}
    catch(x){b.disabled=false;toast(S.keys?"Couldn't open it yet. Check the connection.":"This phone doesn't have the key you accepted with. Open Legacy on that phone.");}
  }
  else if(a==="delall"){
    if(b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Tap again: delete everything in Legacy";return;}
    b.disabled=true;
    for(var i=0;i<mine.length;i++){await G(mine[i].id).collection("copy").doc("data").delete().catch(function(){});await G(mine[i].id).delete().catch(function(){});}
    for(i=0;i<shared.length;i++)await G(shared[i].id).delete().catch(function(){});
    tab="file";await K.deleteAppData();toast("Your Legacy data is deleted. Your Pixora login still works.");
  }
  else if(a==="export")K.exportCopy();
  else if(a==="feedback"){if(window.PixoraFeedback)PixoraFeedback.open("legacy","Legacy");}
  else if(a==="join")K.joinAccount();
  else if(a==="signout"){unsubs.forEach(function(u){u();});unsubs=[];K.signOut();}
  }catch(x){b.disabled=false;toast("Couldn't do that. Check the connection and try again.");}
  if(!$("#dlg").open)fillCodes();
});
$("#tabs").addEventListener("click",function(e){var b=e.target.closest("[data-tab]");if(!b)return;tab=b.dataset.tab;viewing=null;render();fillCodes();K.track("tab_"+tab);});

/* An invite link: #t=<grant id>.<secret>. Read it once and take it out of the address bar. */
(function(){var m=/^#t=([A-Za-z0-9]{10,40})\.([A-Za-z0-9_-]{16,40})$/.exec(location.hash);
  if(m){try{sessionStorage.setItem("legacy-join",m[1]+"."+m[2]);}catch(e){}history.replaceState(null,"",location.pathname);}})();
function pendingJoin(){try{var v=sessionStorage.getItem("legacy-join");sessionStorage.removeItem("legacy-join");return v?v.split("."):null;}catch(e){return null;}}

K.boot({
  app:"legacy",title:"Legacy",version:"legacy-v1",blurb:"Where your will is, who to call, insurance and wishes, for the people you trust.",
  clean:L.clean,
  exportable:function(s){return {me:s.me,items:s.items,wishes:s.wishes,reviewed:s.reviewed,ts:s.ts};},
  restore:function(cur,f){f.grants=cur.grants;f.invites=cur.invites;f.keys=cur.keys;return f;},
  onOpen:function(s,o){S=s;if(o&&o.fresh){mine=[];shared=[];copied={};}viewing=null;listen();render();fillCodes();
    var j=pendingJoin();if(j)joinFlow(j[0],j[1]);},
  onRemote:function(s){S=s;queueCopies();rerender();fillCodes();},
  onStatus:function(t){var st=$("#st");if(st)st.textContent=t;},
  onGate:function(shown){$("#app").hidden=shown;$("#tabs").hidden=shown;},
  /* For Pixora Today: only how complete and fresh the file is, never what's in it. */
  summary:function(s){return {d:iso(),n:L.count(s),reviewed:s.reviewed,due:L.reviewDue(s,iso())};}
});

document.addEventListener("change",function(e){
  if(e.target.id!=="restore"||!e.target.files[0])return;
  var f=e.target.files[0],r=new FileReader();e.target.value="";
  r.onload=function(){
    if(!confirm("Replace what's in Legacy now with this copy? What's here now is replaced."))return;
    try{K.restoreCopy(String(r.result));toast("Restored from your copy.");}
    catch(x){toast(x&&x.code==="wrongapp"?"That copy is from "+(x.app||"another app")+", not Legacy.":"That file isn't a Legacy copy.");}
  };r.readAsText(f);
});
