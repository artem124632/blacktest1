// Lightbox
document.addEventListener('click', e => {
  const t = e.target.closest('[data-lightbox]');
  if (t) {
    const src = t.dataset.src || t.querySelector('img')?.src;
    if (!src) return;
    const m = document.getElementById('lightbox');
    m.querySelector('img').src = src;
    m.classList.add('open');
  }
  if (e.target.matches('.modal, .modal .close')) {
    e.target.closest('.modal').classList.remove('open');
  }
});

// Reviews
async function loadReviews(product='') {
  const url = product ? `/api/reviews?product=${product}` : '/api/reviews';
  const r = await fetch(url); const data = await r.json();
  const wrap = document.getElementById('reviews-list');
  if (!wrap) return;
  wrap.innerHTML = data.map(r => `
    <div class="review">
      <span class="pill">${r.product.toUpperCase()}</span>
      <div class="head">
        <img src="${r.avatar||'https://api.dicebear.com/7.x/identicon/svg?seed='+r.user}" alt="">
        <div class="meta"><b>${r.user}</b><span>${r.created}</span></div>
      </div>
      <div class="stars">${'★'.repeat(r.rating)}${'☆'.repeat(5-r.rating)}</div>
      <p>${r.text.replace(/</g,'&lt;')}</p>
    </div>`).join('') || '<p style="text-align:center;color:var(--muted)">Пока нет отзывов — будьте первым!</p>';
}

const reviewForm = document.getElementById('review-form');
if (reviewForm) {
  let rating = 5;
  const rpick = reviewForm.querySelector('.rating-pick');
  const render = () => { rpick.innerHTML = [1,2,3,4,5].map(i=>`<span class="${i<=rating?'on':''}" data-r="${i}">★</span>`).join(''); };
  render();
  rpick.addEventListener('click', e => { if(e.target.dataset.r){rating=+e.target.dataset.r;render();} });
  reviewForm.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = new FormData(reviewForm);
    const r = await fetch('/api/reviews', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({product: fd.get('product'), text: fd.get('text'), rating})
    });
    if (r.status === 401) { alert('Войдите, чтобы оставить отзыв'); location.href='/login'; return; }
    if (!r.ok) { alert('Ошибка'); return; }
    reviewForm.reset(); rating=5; render(); loadReviews();
  });
  loadReviews();
}

// Popup banner
window.addEventListener('load', () => {
  const popup = document.getElementById('site-popup');
  if (popup && !sessionStorage.getItem('popup_seen')) {
    setTimeout(() => { popup.classList.add('open'); sessionStorage.setItem('popup_seen','1'); }, 1500);
  }
});

/* ====== АНТИ-ВОР (анти-копирование / DevTools) ====== */
(function(){
  const isAdminPanel = location.pathname.startsWith('/admin');
  // Не блокируем в админке — там нужно работать
  if (isAdminPanel) return;

  // блок правой кнопки
  document.addEventListener('contextmenu', e => e.preventDefault());
  // блок F12, Ctrl+U, Ctrl+S, Ctrl+Shift+I/J/C
  document.addEventListener('keydown', e => {
    const k = e.key.toLowerCase();
    if (e.key === 'F12') return e.preventDefault();
    if ((e.ctrlKey||e.metaKey) && ['u','s'].includes(k)) return e.preventDefault();
    if ((e.ctrlKey||e.metaKey) && e.shiftKey && ['i','j','c'].includes(k)) return e.preventDefault();
  });
  // блок копирования/вырезания/перетаскивания
  ['copy','cut','dragstart','selectstart'].forEach(ev =>
    document.addEventListener(ev, e => { if (!e.target.closest('input,textarea,[contenteditable]')) e.preventDefault(); })
  );
  // защита от iframe-кражи (clickjacking)
  if (window.top !== window.self) { try { window.top.location = window.self.location } catch(_) { document.body.innerHTML=''; } }
})();
