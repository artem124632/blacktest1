// Seasonal particles: summer | newyear | halloween
(function(){
  const eff = document.body.dataset.effect;
  if (!eff || eff === 'none') return;
  const c = document.getElementById('particles');
  if (!c) return;
  const ctx = c.getContext('2d');
  let W,H,parts=[];
  const resize=()=>{W=c.width=innerWidth;H=c.height=innerHeight};
  resize(); addEventListener('resize',resize);

  const CONF = {
    summer: {emoji:['☀️','🌴','🌊','🍹','🌺'], count:24, ySpeed:[0.2,0.6]},
    newyear: {emoji:['❄','❅','❆','✦','*'], count:80, ySpeed:[0.4,1.4], color:'#bfe7ff'},
    halloween: {emoji:['🎃','👻','🦇','🕷','💀'], count:22, ySpeed:[0.3,0.9]}
  }[eff] || null;
  if (!CONF) return;

  for (let i=0;i<CONF.count;i++) parts.push({
    x:Math.random()*W, y:Math.random()*H,
    s:14+Math.random()*22, vy:CONF.ySpeed[0]+Math.random()*(CONF.ySpeed[1]-CONF.ySpeed[0]),
    vx:(Math.random()-.5)*0.4, em:CONF.emoji[Math.floor(Math.random()*CONF.emoji.length)],
    r:Math.random()*Math.PI*2, vr:(Math.random()-.5)*0.02
  });

  (function loop(){
    ctx.clearRect(0,0,W,H);
    parts.forEach(p=>{
      p.x+=p.vx; p.y+=p.vy; p.r+=p.vr;
      if (p.y>H+30){p.y=-30;p.x=Math.random()*W}
      if (p.x>W+30)p.x=-30; if (p.x<-30)p.x=W+30;
      ctx.save(); ctx.translate(p.x,p.y); ctx.rotate(p.r);
      ctx.font=`${p.s}px serif`; ctx.fillStyle=CONF.color||'#fff';
      ctx.fillText(p.em,0,0); ctx.restore();
    });
    requestAnimationFrame(loop);
  })();
})();
