(() => {
 'use strict';
 const root=document.getElementById('ps-visit-screen'),status=document.getElementById('visit-status'),retry=document.getElementById('visit-retry');
 let widget=null,busy=false,finished=false,blocked=false,controller=null;
 const fail='確認を完了できませんでした。通信環境やCookie設定をご確認のうえ、もう一度お試しください。';
 const message=text=>{status.textContent=text;};
 function error(text=fail){blocked=true;root.classList.add('failed');message(text);retry.hidden=false;}
 // A successful POST must produce the next server page; never loop forever if
 // session cookies cannot be retained. No URL, CSRF token or credential is stored.
 const navigationKey='ps-visit-navigation';
 try{const at=Number(sessionStorage.getItem(navigationKey));sessionStorage.removeItem(navigationKey);if(at>0&&Date.now()-at<30000)error('確認結果を保存できませんでした。Cookieを有効にして、もう一度お試しください。');}catch(e){}
 async function verify(token){
  if(busy||finished||blocked)return;
  busy=true;message('接続を確認しています。まもなくページへ進みます。');
  controller=new AbortController();const timer=setTimeout(()=>controller.abort(),12000);
  try{
   const url=new URL(root.dataset.visitUrl,location.href);if(url.origin!==location.origin)throw new Error();
   const response=await fetch(url.href,{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal,
    headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({_token:root.dataset.visitCsrf,turnstile_token:token})});
   const data=await response.json();if(!response.ok||data.ok!==true)throw new Error();
   finished=true;root.classList.add('success');message('確認できました。ページへ進みます。');
   try{sessionStorage.setItem(navigationKey,String(Date.now()));}catch(e){}
   // Same URL, query and fragment. No return_url parameter or external redirect.
   location.reload();
  }catch(e){error();}finally{clearTimeout(timer);busy=false;controller=null;}
 }
 retry.addEventListener('click',()=>{
  if(busy||finished)return;
  if(!window.turnstile||widget===null){location.reload();return;}
  blocked=false;root.classList.remove('failed');retry.hidden=true;message('もう一度、接続を確認しています。');turnstile.reset(widget);
 });
 window.psVisitReady=()=>{
  if(widget!==null||blocked)return;
  widget=turnstile.render('#visit-widget',{sitekey:root.dataset.sitekey,action:'visit',appearance:'interaction-only',theme:'dark',language:'ja',size:'flexible','response-field':false,
   callback:verify,'before-interactive-callback':()=>message('確認のため、「私はロボットではありません」にチェックを入れてください。'),
   'expired-callback':()=>{if(!busy&&!finished)error('確認の有効時間が切れました。もう一度お試しください。');},
   'timeout-callback':()=>{if(!finished)error();},
   'error-callback':()=>{if(!finished)error('安全確認に接続できません。通信環境を確認して、もう一度お試しください。');return true;}
  });
 };
 setTimeout(()=>{if(!finished&&!busy&&!blocked)error(widget===null?'安全確認を読み込めませんでした。通信環境を確認して、もう一度お試しください。':'確認に時間がかかっています。チェック欄が表示されていないかご確認ください。');},25000);
 window.addEventListener('pagehide',()=>{if(controller)controller.abort();});
})();
