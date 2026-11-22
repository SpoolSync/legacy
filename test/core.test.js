var L=require("../legacy-core.js"),assert=require("assert"),n=0;function t(a,f){f();n++;console.log("ok  "+a);}
t("last 4 only",function(){assert.strictEqual(L.last4("1234 5678 9012"),"9012");assert.strictEqual(L.last4("ab"),"");});
t("cleaning trims and strips unknown fields",function(){var s=L.clean({items:{insurance:[{id:"a",insurer:"Sun Life",last4:"998877",x:"drop"}],nope:[{id:"z"}]},grants:{g:{k:"abc"}}});
  assert.strictEqual(s.items.insurance[0].last4,"8877");assert.ok(!("x" in s.items.insurance[0]));assert.ok(!s.items.nope);assert.strictEqual(s.grants.g.k,"abc");});
t("flags full numbers and passwords, not phone numbers",function(){
  assert.ok(L.risky("card 4520 1234 5678 9012"));assert.ok(L.risky("SIN 123-456-789"));assert.ok(L.risky("password: hunter2"));
  assert.ok(!L.risky("Call 416-555-0199"));assert.ok(!L.risky("(647) 555-0101"));assert.ok(!L.risky("Box 1123 at TD King St"));});
t("shared copy has no keys or invites",function(){var s=L.clean({me:{name:"S"},grants:{g:{k:"x"}},invites:{g:"t"},keys:{priv:{},pub:"p"}});var c=L.shareable(s);
  assert.ok(!c.grants&&!c.invites&&!c.keys);assert.strictEqual(c.me.name,"S");});
t("yearly review",function(){assert.ok(L.reviewDue(L.clean({}),"2026-11-22"));assert.ok(!L.reviewDue(L.clean({reviewed:"2026-03-01"}),"2026-11-22"));assert.ok(L.reviewDue(L.clean({reviewed:"2025-11-01"}),"2026-11-22"));});
console.log(n+" tests passed");
