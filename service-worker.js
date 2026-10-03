const CACHE='university-leaderboard-nonblocking-load-v1';
const CORE=['./manifest.webmanifest','./icon.svg'];

self.addEventListener('install',event=>{
  event.waitUntil(
    caches.open(CACHE)
      .then(cache=>cache.addAll(CORE))
      .then(()=>self.skipWaiting())
  );
});

self.addEventListener('activate',event=>{
  event.waitUntil(
    caches.keys()
      .then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
      .then(()=>self.clients.claim())
  );
});

self.addEventListener('fetch',event=>{
  if(event.request.method!=='GET') return;
  const url=new URL(event.request.url);
  if(url.origin!==self.location.origin) return;

  if(url.pathname.endsWith('/login') || url.pathname.includes('/auth/') || url.pathname.includes('/api/')){
    event.respondWith(fetch(event.request));
    return;
  }

  if(event.request.mode==='navigate'){
    event.respondWith((async()=>{
      try{
        const response=await fetch(event.request);
        const finalUrl=new URL(response.url);
        if(response.ok && !finalUrl.pathname.endsWith('/login')){
          const cache=await caches.open(CACHE);
          await cache.put('./index.html',response.clone());
        }
        return response;
      }catch{
        const cached=await caches.match('./index.html');
        if(cached) return cached;
        return new Response(
          '<!doctype html><meta charset="utf-8"><title>Offline</title><p style="font-family:sans-serif;padding:2rem">این دستگاه هنوز نسخهٔ آفلاین برنامه را ذخیره نکرده است. یک‌بار در حالت آنلاین وارد شوید.</p>',
          {headers:{'Content-Type':'text/html; charset=utf-8'},status:503}
        );
      }
    })());
    return;
  }

  event.respondWith((async()=>{
    const cached=await caches.match(event.request);
    if(cached) return cached;
    try{
      const response=await fetch(event.request);
      if(response.ok){
        const cache=await caches.open(CACHE);
        cache.put(event.request,response.clone());
      }
      return response;
    }catch{
      return new Response('',{status:503});
    }
  })());
});
