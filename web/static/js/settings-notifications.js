
document.getElementById('settings-theme').addEventListener('click',function(){var t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;try{localStorage.setItem('icevirtue-theme',t)}catch(e){}});
document.getElementById('settings-logout').addEventListener('click',async function(){try{await fetch('/api/logout',{method:'POST',credentials:'same-origin'})}catch(e){}location.href='/login';});
window.addEventListener('pageshow',function(e){if(e.persisted)location.reload()});

// ---- Notification bell (matches the dashboard toolbar) ----
(function(){
  var STYLE={scan_started:{cls:'ok',icon:'check'},scan_finished:{cls:'ok',icon:'check'},scan_halted:{cls:'crit',icon:'alert'},credentials:{cls:'info',icon:'key'}};
  var ICONS={check:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',alert:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',key:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.5 12.5 7-7M17 3l3 3-3 3"/></svg>'};
  var items=[],unread=0;
  function rel(iso){var d=new Date(iso);if(isNaN(d.getTime()))return '';var s=Math.floor((Date.now()-d.getTime())/1000);if(s<60)return 'just now';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}
  function badge(n){unread=Math.max(0,n);var b=document.getElementById('notif-badge');b.textContent=unread>99?'99+':String(unread);b.classList.toggle('hidden',unread===0);}
  function render(){var list=document.getElementById('notif-list');list.replaceChildren();document.getElementById('notif-empty').classList.toggle('hidden',items.length>0);var mr=document.getElementById('notif-markread');if(mr)mr.parentElement.classList.toggle('hidden',items.length===0);document.getElementById('notif-count').textContent=unread?unread+' unread':'';
    items.forEach(function(n){var st=STYLE[n.kind]||{cls:'info',icon:'check'};var row=document.createElement('div');row.className='notif-item'+(n.read?'':' unread');row.setAttribute('role','button');row.tabIndex=0;
      var ic=document.createElement('div');ic.className='notif-ic '+st.cls;ic.innerHTML=ICONS[st.icon]||ICONS.check;
      var body=document.createElement('div');body.className='notif-body';var t=document.createElement('div');t.className='notif-title';t.textContent=n.title||'';var sub=document.createElement('div');sub.className='notif-sub';sub.textContent=n.body||n.host||'';var tm=document.createElement('div');tm.className='notif-time';tm.textContent=rel(n.created_at);body.append(t,sub,tm);
      var x=document.createElement('button');x.className='notif-x';x.setAttribute('aria-label','Dismiss');x.innerHTML='&times;';x.addEventListener('click',function(e){e.stopPropagation();dismiss(n.id);});
      var act=function(){markRead(n.id);};row.addEventListener('click',act);row.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();act();}});
      row.append(ic,body,x);list.appendChild(row);});}
  async function load(){try{var r=await fetch('/api/notifications',{credentials:'same-origin'});if(!r.ok)return;var d=await r.json();items=d.data||[];badge(d.unread||0);render();}catch(e){}}
  window.toggleNotifPanel=function(ev){if(ev)ev.stopPropagation();var p=document.getElementById('notif-panel');var open=p.classList.contains('hidden');p.classList.toggle('hidden',!open);document.getElementById('notif-bell').setAttribute('aria-expanded',String(open));if(open)load();};
  async function markRead(id){var n=items.find(function(x){return x.id===id;});if(n&&!n.read){n.read=true;badge(unread-1);render();}try{await fetch('/api/notifications/'+id+'/read',{method:'POST',credentials:'same-origin'});}catch(e){}}
  window.markAllNotifsRead=async function(){items.forEach(function(n){n.read=true;});badge(0);render();try{await fetch('/api/notifications/read',{method:'POST',credentials:'same-origin'});}catch(e){}};
  async function dismiss(id){var was=items.some(function(x){return x.id===id&&!x.read;});items=items.filter(function(x){return x.id!==id;});if(was)badge(unread-1);render();try{await fetch('/api/notifications/'+id,{method:'DELETE',credentials:'same-origin'});}catch(e){}}
  window.deleteAllNotifs=async function(){items=[];badge(0);render();try{await fetch('/api/notifications',{method:'DELETE',credentials:'same-origin'});}catch(e){}};
  document.addEventListener('click',function(e){var w=document.getElementById('notif-wrap'),p=document.getElementById('notif-panel');if(w&&p&&!p.classList.contains('hidden')&&!w.contains(e.target)){p.classList.add('hidden');document.getElementById('notif-bell').setAttribute('aria-expanded','false');}});
  load();
})();

