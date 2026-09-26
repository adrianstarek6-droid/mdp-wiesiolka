self.addEventListener("push",event=>{
 let d={title:"MDP WIESIÓŁKA",body:"Nowa informacja",url:"/"};
 try{d=event.data.json()}catch(e){}
 event.waitUntil(self.registration.showNotification(d.title,{body:d.body,icon:"/icon.svg",badge:"/icon.svg",data:{url:d.url||"/"}}))
});
self.addEventListener("notificationclick",event=>{event.notification.close();event.waitUntil(clients.matchAll({type:"window",includeUncontrolled:true}).then(cs=>{for(const c of cs)if("focus"in c)return c.focus();return clients.openWindow(event.notification.data?.url||"/")}))});
