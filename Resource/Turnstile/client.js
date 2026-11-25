(() => {
 'use strict';
 const states=[],records=new WeakMap(),nativeSubmit=HTMLFormElement.prototype.submit;
 const script=document.getElementById('ps-turnstile-script');
 const formWait=(Number(script.dataset.formWaitSeconds)||20)*1000;
 const fail='安全確認が完了しません。表示されたチェック、通信環境を確認して、もう一度お試しください。';
 function message(s,text){const status=s.box.querySelector('.ps-turnstile-status');status.textContent=text;status.hidden=s.box.dataset.appearance==='interaction-only'&&!/操作が必要|完了しません|接続できません|読み込めません/.test(text);}
 function reset(s){s.token='';message(s,'送信前の安全確認を進めています。必要な場合だけチェックが表示されます。');if(s.id!==null)turnstile.reset(s.id);}
 function record(form){if(!records.has(form))records.set(form,{prepared:false,resuming:false,nativeSubmitted:false,pending:false});return records.get(form);}
 document.querySelectorAll('.ps-turnstile').forEach(box=>{
  box.querySelector('.ps-turnstile-status').hidden=box.dataset.appearance==='interaction-only';
  const forms=Array.from(document.querySelectorAll('form[data-ps-turnstile-action]')).filter(f=>f.dataset.psTurnstileAction===box.dataset.action);
  states.push({box,forms,form:box.closest('form'),id:null,token:'',pending:null,visitStarted:false});
 });
 async function take(s,refresh){
  let token=s.token;
  if(!token)token=await new Promise((resolve,reject)=>{
   if(s.pending){reject(new Error('安全確認中です。しばらくお待ちください。'));return;}
   message(s,'送信前の安全確認を進めています。必要な場合はチェックしてください。');
   const waiter={resolve,reject,timer:null};s.pending=waiter;
   waiter.timer=setTimeout(()=>{if(s.pending===waiter){s.pending=null;message(s,fail);reject(new Error(fail));}},formWait);
  });
  s.token='';message(s,'安全確認済みです。この操作を送信しています。');if(refresh)reset(s);return token;
 }
 function field(form,token){let el=form.querySelector('input[name="cf-turnstile-response"]');if(!el){el=document.createElement('input');el.type='hidden';el.name='cf-turnstile-response';form.appendChild(el);}el.value=token;}
 function hideOverlay(){if(typeof window.loadingOverlay==='function')window.loadingOverlay('hide');}
 function watchCancelled(s,form,event){setTimeout(()=>{const rec=record(form);if(event.defaultPrevented&&rec.prepared&&!rec.nativeSubmitted){rec.prepared=false;const el=form.querySelector('[name="cf-turnstile-response"]');if(el)el.value='';reset(s);hideOverlay();}},0);}
 function consumeNow(s,form){const token=s.token;s.token='';field(form,token);record(form).prepared=true;message(s,'安全確認済みです。この操作を送信しています。');}
 async function admit(s,form,submitter,viaNative=false){
  const rec=record(form);if(rec.pending||rec.prepared)return;rec.pending=true;hideOverlay();
  const locked=submitter&&!submitter.disabled;if(locked)submitter.disabled=true;
  try{
   const token=await take(s,false);
   if(!viaNative&&!(submitter&&submitter.formNoValidate)&&!form.checkValidity()){s.token=token;form.reportValidity();return;}
   field(form,token);rec.prepared=true;
   if(locked)submitter.disabled=false;
   if(viaNative){rec.nativeSubmitted=true;nativeSubmit.call(form);}
   else{rec.resuming=true;form.requestSubmit(submitter||undefined);}
  }catch(e){message(s,e.message);hideOverlay();}
  finally{rec.pending=false;if(!rec.prepared)hideOverlay();if(locked)submitter.disabled=false;}
 }
 for(const s of states)for(const form of s.forms)form.addEventListener('submit',e=>{
  const rec=record(form);
  if(rec.resuming){rec.resuming=false;watchCancelled(s,form,e);return;}
  if(rec.pending||rec.prepared){e.preventDefault();return;}
  if(s.token){consumeNow(s,form);watchCancelled(s,form,e);return;}
  e.preventDefault();admit(s,form,e.submitter);
 },true);
 HTMLFormElement.prototype.submit=function(){
  const s=states.find(x=>x.forms.includes(this));if(!s)return nativeSubmit.call(this);
  const rec=record(this);if(rec.nativeSubmitted)return;
  if(rec.prepared){rec.nativeSubmitted=true;return nativeSubmit.call(this);}
  if(s.token){consumeNow(s,this);rec.nativeSubmitted=true;return nativeSubmit.call(this);}
  admit(s,this,null,true);
 };
 async function visit(s){
  if(s.visitStarted)return;s.visitStarted=true;const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),12000);
  try{const token=await take(s,false);const r=await fetch(s.box.dataset.visitUrl,{method:'POST',credentials:'same-origin',signal:abort.signal,headers:{'Content-Type':'application/json'},body:JSON.stringify({_token:s.box.dataset.visitCsrf,turnstile_token:token})});const d=await r.json();if(!r.ok||!d.ok)throw new Error(fail);s.box.hidden=true;}
  catch(e){message(s,fail);s.visitStarted=false;}finally{clearTimeout(timer);}
 }
 window.psTurnstileReady=()=>states.forEach(s=>{
  const widget=document.createElement('div');s.box.appendChild(widget);
  s.id=turnstile.render(widget,{sitekey:s.box.dataset.sitekey,action:s.box.dataset.action,appearance:s.box.dataset.appearance||'interaction-only',language:'ja',size:'flexible','response-field':false,
   callback:token=>{s.token=token;message(s,'安全確認が完了しました。');if(s.pending){const p=s.pending;s.pending=null;clearTimeout(p.timer);p.resolve(token);}if(s.box.dataset.visit==='true')visit(s);},
   'before-interactive-callback':()=>message(s,'操作が必要です。「私はロボットではありません」を確認してください。'),
   'expired-callback':()=>{s.token='';message(s,'安全確認を更新しています。必要な場合だけチェックが表示されます。');},
   'error-callback':()=>{s.token='';message(s,'安全確認に接続できません。通信環境を確認して再読み込みしてください。');if(s.pending){const p=s.pending;s.pending=null;clearTimeout(p.timer);p.reject(new Error('安全確認に接続できません。'));}return true;}
  });
 });
 const customerPath=script.dataset.checkoutCustomer;
 if(customerPath&&window.jQuery)window.jQuery.ajaxPrefilter((options,original,xhr)=>{
  const url=new URL(options.url,location.href);
  if(url.origin!==location.origin||url.pathname!==new URL(customerPath,location.href).pathname||String(options.type).toUpperCase()!=='POST')return;
  const s=states.find(x=>x.box.dataset.action==='checkout');
  if(!s||!s.token){xhr.abort('turnstile_pending');if(s)message(s,'安全確認の完了後に、もう一度変更してください。');return;}
  options.data=(options.data?options.data+'&':'')+'cf-turnstile-response='+encodeURIComponent(s.token);reset(s);
 });
 window.psTurnstile={reset:()=>{const s=states.find(x=>x.box.dataset.api==='true');if(s)reset(s);},take:async(refresh=true)=>{const s=states.find(x=>x.box.dataset.api==='true');if(!s)throw new Error('安全確認の画面を再読み込みしてください。');return take(s,refresh);}};
 window.addEventListener('pageshow',e=>{if(e.persisted){document.querySelectorAll('form[data-ps-turnstile-action]').forEach(f=>{records.delete(f);const field=f.querySelector('[name="cf-turnstile-response"]');if(field)field.value='';});states.forEach(reset);}});
 setTimeout(()=>states.forEach(s=>{if(s.id===null)message(s,'安全確認を読み込めませんでした。通信環境や拡張機能を確認して再読み込みしてください。');}),15000);
})();
