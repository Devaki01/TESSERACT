const $=s=>document.querySelector(s);
const APPR=['Asha (CISO)','Ravi (PKI lead)','Meera (NetOps)','Imran (SecOps)','Tara (Audit)'];
const M=3,N=5,ALLOW='college.edu';
const R=[
 {id:1,d:['api.college.edu'],who:'svc-api@college.edu',kind:'Renewal',h:24,key:'EC P-384',val:'http-01 passed',truth:'real',first:false,note:'Already approved identity'},
 {id:2,d:['*.college.edu'],who:'netadmin@college.edu',kind:'New wildcard',h:24,key:'EC P-256',val:'dns-01 passed',truth:'real',first:true,note:'Wildcard needs a human quorum'},
 {id:3,d:['*.google.com'],who:'203.0.113.77 (unknown)',kind:'New wildcard',h:72,key:'RSA 2048',val:'none',truth:'fake',first:true,note:'Looks like the DigiNotar rogue certificate'},
 {id:4,d:['library.college.edu'],who:'lib-admin@college.edu',kind:'Renewal',h:168,key:'EC P-256',val:'http-01 passed',truth:'real',first:false,note:'Misconfigured: 7-day lifetime requested'},
 {id:5,d:['vpn.college-edu.net'],who:'promo@mailbox.ru',kind:'New domain',h:48,key:'EC P-256',val:'http-01 passed',truth:'fake',first:true,note:'Look-alike domain, passes validation'},
 {id:6,d:['portal.college.edu'],who:'svc-portal@college.edu',kind:'Renewal',h:24,key:'EC P-256',val:'http-01 passed',truth:'real',first:false,note:'Routine renewal'},
 {id:7,d:['lab.cs.college.edu'],who:'prof.rao@college.edu',kind:'New domain',h:24,key:'RSA 1024',val:'dns-01 passed',truth:'real',first:true,note:'Legitimate owner, weak key'},
 {id:8,d:['login.college.edu','mail.college.edu'],who:'10.9.4.12 (DMZ host)',kind:'New domain',h:24,key:'EC P-384',val:'none',truth:'fake',first:true,note:'Request came from a compromised DMZ box'}
].map(r=>({...r,st:'pending',votes:Array(N).fill(null),tag:null}));
let sealed=true,shares=new Set(),sel=1,log=[],certs=[],S={rogue:0,blocked:0},serial=4000,busy=false;
const h53=(s,x=0)=>{let a=0xdeadbeef^x,b=0x41c6ce57^x;for(let i=0;i<s.length;i++){const c=s.charCodeAt(i);a=Math.imul(a^c,2654435761);b=Math.imul(b^c,1597334677)}a=Math.imul(a^a>>>16,2246822507)^Math.imul(b^b>>>13,3266489909);b=Math.imul(b^b>>>16,2246822507)^Math.imul(a^a>>>13,3266489909);return(4294967296*(2097151&b)+(a>>>0)).toString(16).padStart(14,'0')};
const now=()=>new Date().toLocaleTimeString([], {hour12:false});
function add(msg,bad){const prev=log.length?log[log.length-1].h:'0';log.push({t:now(),msg,bad,h:h53(prev+msg)});drawLog()}
function toast(m){const t=$('#toast');t.textContent=m;t.className='s';clearTimeout(toast.i);toast.i=setTimeout(()=>t.className='',2200)}
const checks=r=>{const dom=r.d.every(x=>x.replace('*.','')===ALLOW||x.endsWith('.'+ALLOW));
 const k=r.key.startsWith('EC')||(r.key.startsWith('RSA')&&parseInt(r.key.slice(4))>=2048);
 return[['Domain is in allow-list ('+ALLOW+')',dom],['Validity within 72h cap ('+r.h+'h)',r.h<=72],['Key type acceptable ('+r.key+')',k],['ACME challenge ('+r.val+')',r.val!=='none'],['Not a first-ever high-value issuance',!r.first||r.kind==='New domain'&&dom]]};
const pass=r=>checks(r).every(c=>c[1]);
const PIPE=[['ACME RA','DMZ, holds no keys'],['Approval gateway','M-of-N policy'],['Signing CA','re-verifies approvals'],['SoftHSM','non-extractable key'],['OCSP and audit','staple + hash chain']];
function drawPipe(on,bad){$('#pipe').innerHTML=PIPE.map((p,i)=>`<div class="node ${on===i?(bad?'bad':'on'):''}"><b>${p[0]}</b><span>${p[1]}</span></div>`).join('<span class="arrow">&rsaquo;</span>')}
function stage(seq,bad){seq.forEach((n,i)=>setTimeout(()=>drawPipe(n,bad&&i===seq.length-1),i*450));setTimeout(()=>drawPipe(-1),seq.length*450+500)}
function drawShares(){$('#shares').innerHTML=[1,2,3,4,5].map(i=>`<button class="${shares.has(i)?'on':''}" data-s="${i}" ${sealed?'':'disabled'}>${i}</button>`).join('');
 const e=$('#hsm');e.textContent=sealed?`SoftHSM sealed (${shares.size}/${M} shares)`:'SoftHSM unsealed';e.className='tag '+(sealed?'t-bad':'t-ok')}
function drawQueue(){$('#queue').innerHTML=R.map(r=>{const ok=r.tag&&((r.tag==='legit')===(r.truth==='real'));
 return`<div class="req ${r.id===sel?'sel':''}" data-r="${r.id}"><div class="d">${r.d.join(', ')}</div><div class="sub">${r.kind} &middot; ${r.who}</div>
 <span class="tag ${r.st==='issued'?'t-ok':r.st==='rejected'?'t-bad':'t-in'}">${r.st}</span>${r.tag?`<span class="tag ${r.tag==='legit'?'t-ok':r.tag==='suspicious'?'t-wa':'t-bad'}">tagged ${r.tag}</span>`:''}${r.st!=='pending'&&r.tag?`<span class="tag ${ok?'t-ok':'t-bad'}">${ok?'tag correct':'tag wrong'}</span>`:''}</div>`}).join('')}
function drawStats(){const c=R.filter(r=>r.tag&&r.st!=='pending');const right=c.filter(r=>(r.tag==='legit')===(r.truth==='real')).length;
 $('#stats').innerHTML=[['Pending',R.filter(r=>r.st==='pending').length],['Issued',R.filter(r=>r.st==='issued').length],['Blocked',S.blocked],['Tag accuracy',c.length?Math.round(right/c.length*100)+'%':'n/a']].map(s=>`<div class="stat"><b>${s[1]}</b><span class="sub">${s[0]}</span></div>`).join('')}
function drawDetail(){const r=R.find(x=>x.id===sel),yes=r.votes.filter(v=>v==='y').length,no=r.votes.filter(v=>v==='n').length;
 $('#detail').innerHTML=`<h2>Request #${r.id}: ${r.d.join(', ')}</h2>
 <div class="sub">${r.kind} from ${r.who} &middot; csr_hash <span class="mono">${h53('csr'+r.id)}</span></div><div class="sub">Gateway note: ${r.note}</div>
 <div style="margin-top:8px">${checks(r).map(c=>`<div class="chk"><span>${c[0]}</span><b class="${c[1]?'t-ok':'t-bad'}">${c[1]?'pass':'fail'}</b></div>`).join('')}</div>
 <div class="row"><span class="sub">Tag this request:</span>
  <button data-t="legit">Legit</button><button data-t="suspicious">Suspicious</button><button data-t="fake">Fake</button></div>
 <h2 style="margin-top:12px">Approvals: ${yes} of ${M} needed (${no} rejections)</h2>
 <div class="bar"><i style="width:${Math.min(yes/M,1)*100}%"></i></div>
 <div class="apps">${APPR.map((a,i)=>`<div class="app ${r.votes[i]||''}"><b>${a}</b><div class="sub">${r.votes[i]==='y'?'Signed (Ed25519)':r.votes[i]==='n'?'Rejected':'Waiting'}</div>
  <div class="row" style="margin:6px 0 0"><button data-v="${i}y" ${r.st!=='pending'||r.votes[i]?'disabled':''}>Approve</button><button data-v="${i}n" ${r.st!=='pending'||r.votes[i]?'disabled':''}>Reject</button></div></div>`).join('')}</div>
 <div class="row"><button id="auto" ${r.st!=='pending'||busy?'disabled':''}>Run committee automatically</button>
 ${r.st!=='pending'?'<span class="tag '+(r.st==='issued'?'t-ok':'t-bad')+'">Outcome: '+r.st+'</span>':''}</div>`}
function drawCerts(){$('#certs').innerHTML=certs.length?certs.map(c=>{const used=Math.floor((Date.now()-c.at)/1000),left=Math.max(c.h*60-used,0);
 return`<tr><td class="mono">${c.sn}</td><td>${c.cn}${c.rogue?' <span class="tag t-bad">rogue</span>':''}</td><td>${c.h}h</td><td>${Math.floor(left/60)}h ${left%60}m</td><td class="${c.rev?'t-bad':'t-ok'}">${c.rev?'revoked':'good (refresh 4h)'}</td><td>${c.rev?'':`<button data-rv="${c.sn}">Revoke</button>`}</td></tr>`}).join(''):'<tr><td colspan="6" class="sub">No certificates yet. Unseal the HSM and approve a request.</td></tr>'}
function drawLog(){const l=$('#log');l.innerHTML=log.map((e,i)=>`<div class="le ${e.bad?'x':''}"><span class="sub">${e.t}</span> ${e.msg}<div class="mono t-mu">#${i} ${e.h}</div></div>`).join('');l.scrollTop=l.scrollHeight}
function all(){drawShares();drawQueue();drawStats();drawDetail();drawCerts()}
function resolve(r){const yes=r.votes.filter(v=>v==='y').length,no=r.votes.filter(v=>v==='n').length;
 if(yes>=M){stage([1,2,3,4]);add(`Gateway released #${r.id}: ${yes} valid signatures`);
  if(!pass(r)){r.st='rejected';S.blocked++;add(`Signer REFUSED #${r.id}: CSR policy violation, even with ${M} approvals`,true);toast('Signer blocked it: policy violation')}
  else{r.st='issued';const sn='0x'+(++serial).toString(16);certs.push({sn,cn:r.d[0],h:Math.min(r.h,72),at:Date.now(),rogue:r.truth==='fake'});
   if(r.truth==='fake'){S.rogue++;add(`Cert ${sn} issued for #${r.id}. Quorum was fooled!`,true)}else add(`Cert ${sn} issued for ${r.d[0]} (${r.h}h), Must-Staple set`)}}
 else if(no>=N-M+1){r.st='rejected';S.blocked++;stage([0,1],true);add(`#${r.id} rejected: ${no} approvers refused, quorum impossible`,r.truth==='real')}
 all()}
function vote(i,v){const r=R.find(x=>x.id===sel);if(sealed){toast('HSM is sealed. Collect 3 key shares first.');return}
 r.votes[i]=v;add(`${APPR[i]} ${v==='y'?'signed':'rejected'} #${r.id} <span class="mono">sig:${h53(APPR[i]+r.id+v).slice(0,10)}</span>`);resolve(r)}
async function auto(){const r=R.find(x=>x.id===sel);if(sealed){toast('HSM is sealed. Collect 3 key shares first.');return}
 busy=true;stage([0,1]);
 for(let i=0;i<N&&r.st==='pending';i++){await new Promise(z=>setTimeout(z,650));if(r.votes[i])continue;
  const good=r.truth==='real'; vote(i,good||i===1?'y':'n')}
 busy=false;all()}
document.addEventListener('click',e=>{const b=e.target.closest('button,.req');if(!b)return;
 if(b.dataset.s){const s=+b.dataset.s;shares.has(s)?shares.delete(s):shares.add(s);add(`Key share ${s} ${shares.has(s)?'submitted':'withdrawn'}`);
  if(shares.size>=M){sealed=false;add('Shamir shares combined: HSM PIN reconstructed, signer unsealed');stage([2,3])}drawShares()}
 else if(b.dataset.r){sel=+b.dataset.r;all()}
 else if(b.dataset.t){const r=R.find(x=>x.id===sel);r.tag=b.dataset.t;add(`Admin tagged #${r.id} as ${r.tag}`);all()}
 else if(b.dataset.v){vote(+b.dataset.v[0],b.dataset.v[1])}
 else if(b.dataset.rv){const c=certs.find(x=>x.sn===b.dataset.rv);c.rev=true;stage([4]);add(`Emergency revocation of ${c.sn}: next staple will say revoked`);drawCerts()}
 else if(b.id==='auto')auto();
 else if(b.id==='vfy'){let p='0',bad=-1;log.forEach((x,i)=>{if(bad<0&&h53(p+x.msg)!==x.h)bad=i;p=x.h});
  bad<0?(add('Chain verified: all hashes consistent'),toast('Chain intact')):(toast('Chain BROKEN at entry #'+bad),add('Verification FAILED at entry #'+bad+': tampering detected',true))}
 else if(b.id==='tmp'){if(log.length<2){toast('Make some log entries first');return}log[1].msg='(edited by attacker) nothing happened here';drawLog();toast('Entry #1 modified. Now click Verify chain.')}
 else if(b.id==='a1'){stage([0,1,3],true);S.blocked++;add('DRILL: DMZ shell tried to reach HSM. Firewall dropped it; key is non-extractable',true);drawStats()}
 else if(b.id==='a2'){stage([1],true);S.blocked++;add('DRILL: forged approval with 1 valid signature. Rejected (needs '+M+')',true);drawStats()}
 else if(b.id==='a3'){const sn='0x'+(++serial).toString(16);certs.push({sn,cn:'bank.example.com',h:24,at:Date.now(),rogue:true});add(`Cert ${sn} for bank.example.com appeared with no matching approval`,true);all();
  setTimeout(()=>{add('CT-style monitor: ALERT, issuance without approval. Auto-revoking '+sn,true);const c=certs.find(x=>x.sn===sn);c.rev=true;stage([4],true);S.blocked++;all()},1400)}});
drawPipe(-1);all();drawLog();setInterval(drawCerts,1000);
add('Console started. HSM sealed, waiting for key holders');
