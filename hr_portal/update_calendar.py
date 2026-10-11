f = r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html"
with open(f,"r",encoding="utf-8") as h: html=h.read()
S,E="<!-- CALENDAR PAGE -->","<!-- PTO PAGE -->"
s,e=html.find(S),html.find(E)
if s==-1 or e==-1: print("ERROR markers not found"); exit(1)
print(f"Found: {s}..{e}")
NEW="""<!-- CALENDAR PAGE -->
      <div class="page" id="page-calendar">
        <div class="page-header"><h1>Calendar</h1><p id="cal-hdr">September 2026</p></div>
        <div class="card" style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <button id="cprev" style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 14px;color:var(--text);cursor:pointer;font-size:13px">&#8592; Prev</button>
            <div id="ctitle" style="font-size:16px;font-weight:700;font-family:'Syne',sans-serif">September 2026</div>
            <button id="cnext" style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 14px;color:var(--text);cursor:pointer;font-size:13px">Next &#8594;</button>
          </div>
          <div id="cgrid" style="display:grid;grid-template-columns:repeat(7,1fr);gap:3px;text-align:center">
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Sun</div><div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Mon</div><div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Tue</div><div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Wed</div><div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Thu</div><div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Fri</div><div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Sat</div>
          </div>
          <div id="cdet" style="display:none;margin-top:12px;padding:12px 14px;background:var(--surface2);border-radius:8px;border:1px solid var(--border)">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
              <strong id="cdet-ttl" style="font-size:14px"></strong>
              <button onclick="document.getElementById('cdet').style.display='none'" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px">&times;</button>
            </div>
            <div id="cdet-body" style="font-size:13px;line-height:1.6"></div>
          </div>
          <div style="display:flex;gap:14px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap">
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(88,166,255,.4);margin-right:4px"></span>Today</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(63,185,80,.2);margin-right:4px"></span>Work Day</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(248,81,73,.25);margin-right:4px"></span>Holiday</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(210,153,34,.3);margin-right:4px"></span>Reminder</span>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
          <div class="card">
            <div class="card-title">&#128203; Reminders &amp; Tasks
              <span id="rem-sync-status" style="float:right;font-size:10px;color:var(--muted);font-weight:400"></span>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
              <input id="rtxt" class="ai-input" placeholder="Reminder or task..." style="flex:1;min-width:100px;font-size:13px">
              <input id="rdate" type="date" class="ai-input" style="width:130px;font-size:13px">
              <select id="rtype" class="ai-input" style="width:120px;font-size:12px">
                <option value="r">&#128276; Reminder</option>
                <option value="t">&#9989; Task</option>
                <option value="m">&#128197; Meeting</option>
                <option value="d">&#128680; Deadline</option>
              </select>
              <button id="radd" style="background:var(--accent);color:#fff;border:none;border-radius:6px;padding:7px 14px;cursor:pointer;font-size:13px;font-weight:500">+ Add</button>
            </div>
            <div id="rlist" style="display:flex;flex-direction:column;gap:6px;max-height:260px;overflow-y:auto">
              <div style="color:var(--muted);font-size:13px">No reminders yet.</div>
            </div>
          </div>

          <div class="card">
            <div class="card-title">&#128221; Notes Pad
              <span id="notes-sync-status" style="float:right;font-size:10px;color:var(--muted);font-weight:400"></span>
            </div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px">
              &#128274; Saved to AI-Prowler server &mdash; visible to HR admin
            </div>
            <textarea id="cnotes" placeholder="Write notes, to-dos, or anything your manager should know..." style="width:100%;min-height:180px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;color:var(--text);font-size:13px;resize:vertical;outline:none;line-height:1.5;box-sizing:border-box"></textarea>
            <div style="margin-top:8px;display:flex;align-items:center;gap:10px">
              <button id="nsave" style="background:var(--accent2);color:#0d1117;border:none;border-radius:6px;padding:7px 16px;cursor:pointer;font-size:12px;font-weight:600">Save Notes</button>
              <span id="nsaved" style="display:none;font-size:11px;color:var(--accent2)">&#10003; Saved to server</span>
            </div>
          </div>
        </div>

        <script>
        (function(){
          var HOL={'2026-01-01':'New Years Day','2026-01-19':'MLK Day','2026-02-16':'Presidents Day','2026-05-25':'Memorial Day','2026-06-19':'Juneteenth','2026-07-04':'Independence Day','2026-09-07':'Labor Day','2026-10-12':'Columbus Day','2026-11-11':'Veterans Day','2026-11-26':'Thanksgiving','2026-11-27':'Day After Thanksgiving','2026-12-25':'Christmas','2027-01-01':'New Years Day','2027-01-18':'MLK Day','2027-02-15':'Presidents Day','2027-05-31':'Memorial Day','2027-06-19':'Juneteenth','2027-07-04':'Independence Day','2027-09-06':'Labor Day','2027-11-25':'Thanksgiving','2027-12-25':'Christmas'};
          var MN=['January','February','March','April','May','June','July','August','September','October','November','December'];
          var DN=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
          var TI={r:'&#128276;',t:'&#9989;',m:'&#128197;',d:'&#128680;'};
          var cs={y:2026,m:8};
          var rems=[];

          function pad(n){return('0'+n).slice(-2);}
          function dk(y,m,d){return y+'-'+pad(m+1)+'-'+pad(d);}
          function session(){try{return JSON.parse(localStorage.getItem('hr_portal_session'));}catch(e){return null;}}
          function headers(){return{'Content-Type':'application/json','X-Employee-Session':JSON.stringify(session())};}

          // ── Load reminders & notes from server ──
          function loadFromServer(){
            var s=session();if(!s)return;
            fetch('/hr-api/calendar/reminders',{headers:headers()})
              .then(function(r){return r.json();})
              .then(function(d){
                if(d.reminders&&Array.isArray(d.reminders)){rems=d.reminders;drawR();draw();}
                document.getElementById('rem-sync-status').textContent='Synced with server';
              }).catch(function(){document.getElementById('rem-sync-status').textContent='Offline';});
            fetch('/hr-api/calendar/notes',{headers:headers()})
              .then(function(r){return r.json();})
              .then(function(d){
                if(typeof d.notes==='string')document.getElementById('cnotes').value=d.notes;
                document.getElementById('notes-sync-status').textContent='Synced with server';
              }).catch(function(){});
          }

          // ── Save reminders to server ──
          function saveRems(){
            var s=session();if(!s)return;
            fetch('/hr-api/calendar/reminders',{method:'POST',headers:headers(),body:JSON.stringify({reminders:rems})})
              .then(function(){document.getElementById('rem-sync-status').textContent='Saved \u2713';})
              .catch(function(){document.getElementById('rem-sync-status').textContent='Save failed';});
          }

          function draw(){
            var y=cs.y,m=cs.m,now=new Date(),ty=now.getFullYear(),tm=now.getMonth(),td=now.getDate();
            var lbl=MN[m]+' '+y;
            document.getElementById('ctitle').textContent=lbl;
            document.getElementById('cal-hdr').textContent=lbl+' \u2014 your schedule at a glance';
            var grid=document.getElementById('cgrid');
            while(grid.children.length>7)grid.removeChild(grid.lastChild);
            var first=new Date(y,m,1).getDay(),last=new Date(y,m+1,0).getDate();
            for(var i=0;i<first;i++){var b=document.createElement('div');b.style.padding='8px';grid.appendChild(b);}
            for(var d=1;d<=last;d++){
              var k=dk(y,m,d),dow=new Date(y,m,d).getDay(),tod=(y===ty&&m===tm&&d===td),hol=HOL[k],wknd=(dow===0||dow===6),dr=rems.filter(function(r){return r.date===k;});
              var cell=document.createElement('div');
              cell.style.cssText='padding:5px 2px;border-radius:6px;cursor:pointer;font-size:13px;min-height:40px;display:flex;flex-direction:column;align-items:center;gap:2px;';
              if(tod){cell.style.background='rgba(88,166,255,.2)';cell.style.border='1px solid var(--accent)';cell.style.color='var(--accent)';}
              else if(hol){cell.style.background='rgba(248,81,73,.15)';cell.style.color='#f87171';}
              else if(!wknd){cell.style.background='rgba(63,185,80,.1)';cell.style.color='var(--accent2)';}
              else{cell.style.color='var(--muted)';}
              var num=document.createElement('div');num.textContent=d;num.style.fontWeight=tod?'700':'400';cell.appendChild(num);
              if(hol||dr.length>0){var dots=document.createElement('div');dots.style.cssText='display:flex;gap:2px;';if(hol){var p=document.createElement('div');p.style.cssText='width:5px;height:5px;border-radius:50%;background:#f85149;';dots.appendChild(p);}if(dr.length>0){var q=document.createElement('div');q.style.cssText='width:5px;height:5px;border-radius:50%;background:#d29922;';dots.appendChild(q);}cell.appendChild(dots);}
              cell.onmouseover=function(){this.style.filter='brightness(1.3)';};cell.onmouseout=function(){this.style.filter='';};
              (function(day,key,hol,dr){cell.onclick=function(){showDet(day,key,hol,dr);};})(d,k,hol,dr);
              grid.appendChild(cell);
            }
          }

          function showDet(day,key,hol,dr){
            var dow=new Date(key).getDay();
            document.getElementById('cdet-ttl').textContent=DN[dow]+', '+MN[cs.m]+' '+day+', '+cs.y;
            var h='';
            if(hol)h+='<div style="margin-bottom:8px"><span style="background:rgba(248,81,73,.15);color:#f87171;font-size:11px;font-weight:700;padding:3px 10px;border-radius:12px">&#127881; '+hol+'</span></div>';
            if(dr.length>0){h+='<div style="font-weight:600;font-size:12px;color:var(--text);margin-bottom:6px">Reminders:</div>';dr.forEach(function(r){h+='<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border)">'+(TI[r.type||'r']||'&#128276;')+'<span style="font-size:12px;color:var(--text)">'+r.text+'</span></div>';});}
            if(!hol&&dr.length===0)h='<span style="color:var(--muted);font-size:12px">No events for this day.</span>';
            document.getElementById('cdet-body').innerHTML=h;
            document.getElementById('cdet').style.display='block';
          }

          document.getElementById('cprev').onclick=function(){cs.m--;if(cs.m<0){cs.m=11;cs.y--;}draw();};
          document.getElementById('cnext').onclick=function(){cs.m++;if(cs.m>11){cs.m=0;cs.y++;}draw();};

          function drawR(){
            var list=document.getElementById('rlist');
            if(rems.length===0){list.innerHTML='<div style="color:var(--muted);font-size:13px">No reminders yet.</div>';return;}
            var today=new Date().toISOString().slice(0,10);
            var sorted=[].concat(rems).sort(function(a,b){return a.date.localeCompare(b.date);});
            list.innerHTML=sorted.map(function(r,i){return'<div style="display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--surface2);border-radius:6px;border:1px solid var(--border);'+(r.date<today?'opacity:.5':'')+'">'+(TI[r.type||'r']||'&#128276;')+'<div style="flex:1"><div style="font-size:13px;color:var(--text)">'+r.text+'</div><div style="font-size:10px;color:var(--muted)">'+r.date+'</div></div><button onclick="rdel('+i+')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:15px">&times;</button></div>';}).join('');
          }

          window.rdel=function(i){
            var sorted=[].concat(rems).sort(function(a,b){return a.date.localeCompare(b.date);});
            var t=sorted[i];rems=rems.filter(function(r){return!(r.text===t.text&&r.date===t.date);});
            saveRems();drawR();draw();
          };

          document.getElementById('radd').onclick=function(){
            var txt=document.getElementById('rtxt').value.trim(),dt=document.getElementById('rdate').value,tp=document.getElementById('rtype').value;
            if(!txt||!dt){alert('Please enter text and a date.');return;}
            rems.push({text:txt,date:dt,type:tp});
            saveRems();
            document.getElementById('rtxt').value='';document.getElementById('rdate').value='';
            drawR();draw();
          };

          document.getElementById('nsave').onclick=function(){
            var notes=document.getElementById('cnotes').value;
            var s=session();if(!s){alert('Not logged in.');return;}
            fetch('/hr-api/calendar/notes',{method:'POST',headers:headers(),body:JSON.stringify({notes:notes})})
              .then(function(){var m=document.getElementById('nsaved');m.style.display='inline';setTimeout(function(){m.style.display='none';},3000);document.getElementById('notes-sync-status').textContent='Saved \u2713';})
              .catch(function(){alert('Could not save to server.');});
          };

          draw();drawR();
          // Load saved data from server when calendar is shown
          document.addEventListener('DOMContentLoaded',function(){
            var orig=window.navigate;
            window.navigate=function(el,pg,t){
              if(typeof orig==='function')orig(el,pg,t);
              if(pg==='calendar')setTimeout(loadFromServer,100);
            };
          });
          // Also load immediately if calendar is already active
          setTimeout(function(){
            var p=document.getElementById('page-calendar');
            if(p&&p.classList.contains('active'))loadFromServer();
          },500);
        })();
        </script>
      </div>

      """
result=html[:s]+NEW+html[e:]
with open(f,"w",encoding="utf-8") as h: h.write(result)
print("DONE. Size: "+str(len(result)))
