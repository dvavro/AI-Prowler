import json

filepath = r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html"

with open(filepath, "r", encoding="utf-8") as f:
    html = f.read()

START = "<!-- CALENDAR PAGE -->"
END   = "<!-- PTO PAGE -->"

s = html.find(START)
e = html.find(END)
if s == -1 or e == -1:
    print(f"ERROR: markers not found s={s} e={e}")
    exit(1)

print(f"Calendar block found: chars {s}..{e}")

NEW = r"""<!-- CALENDAR PAGE -->
      <div class="page" id="page-calendar">
        <div class="page-header">
          <h1>Calendar</h1>
          <p id="cal-sub">September 2026 &mdash; your schedule at a glance</p>
        </div>

        <div class="card" style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <button id="cal-prev" style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 14px;color:var(--text);cursor:pointer;font-family:inherit;font-size:13px">&larr; Prev</button>
            <div id="cal-title" style="font-family:'Syne',sans-serif;font-size:16px;font-weight:700">September 2026</div>
            <button id="cal-next" style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 14px;color:var(--text);cursor:pointer;font-family:inherit;font-size:13px">Next &rarr;</button>
          </div>
          <div id="cal-grid" style="display:grid;grid-template-columns:repeat(7,1fr);gap:3px;text-align:center">
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Sun</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Mon</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Tue</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Wed</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Thu</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Fri</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Sat</div>
          </div>
          <div id="cal-day-detail" style="display:none;margin-top:12px;padding:12px 14px;background:var(--surface2);border-radius:8px;border:1px solid var(--border)">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
              <strong id="cal-detail-title" style="font-size:14px"></strong>
              <button onclick="document.getElementById('cal-day-detail').style.display='none'" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px">&times;</button>
            </div>
            <div id="cal-detail-body" style="font-size:13px;color:var(--muted)"></div>
          </div>
          <div style="display:flex;gap:14px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap">
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(88,166,255,.35);margin-right:4px"></span>Today</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(63,185,80,.2);margin-right:4px"></span>Work Day</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(248,81,73,.25);margin-right:4px"></span>Holiday</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(210,153,34,.25);margin-right:4px"></span>Reminder</span>
          </div>
        </div>

        <!-- Reminders + Notes panels -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:0">
          <div class="card">
            <div class="card-title">&#128203; Daily Reminders &amp; Tasks</div>
            <div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap">
              <input id="rem-text" class="ai-input" placeholder="Add a reminder or task..." style="flex:1;min-width:120px;font-size:13px">
              <input id="rem-date" type="date" class="ai-input" style="width:130px;font-size:13px">
              <select id="rem-type" class="ai-input" style="width:110px;font-size:12px">
                <option value="reminder">&#128276; Reminder</option>
                <option value="task">&#9989; Task</option>
                <option value="meeting">&#128197; Meeting</option>
                <option value="deadline">&#128680; Deadline</option>
              </select>
              <button id="rem-add-btn" style="background:var(--accent);color:#fff;border:none;border-radius:6px;padding:7px 14px;cursor:pointer;font-size:13px;font-family:inherit;font-weight:500">+ Add</button>
            </div>
            <div id="rem-list" style="display:flex;flex-direction:column;gap:6px;max-height:280px;overflow-y:auto">
              <div style="color:var(--muted);font-size:13px;padding:4px 0">No reminders yet. Add one above.</div>
            </div>
          </div>
          <div class="card">
            <div class="card-title">&#128221; Notes Pad</div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Your personal daily notes</div>
            <textarea id="cal-notes" placeholder="Write notes, to-dos, or anything you want to remember..." style="width:100%;min-height:190px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;color:var(--text);font-family:inherit;font-size:13px;resize:vertical;outline:none;line-height:1.5;box-sizing:border-box"></textarea>
            <div style="display:flex;gap:8px;margin-top:8px;align-items:center">
              <button id="notes-save-btn" style="background:var(--accent2);color:#0d1117;border:none;border-radius:6px;padding:7px 16px;cursor:pointer;font-size:12px;font-family:inherit;font-weight:600">Save Notes</button>
              <span id="notes-saved-msg" style="display:none;font-size:11px;color:var(--accent2)">&#10003; Saved!</span>
            </div>
          </div>
        </div>

        <script>
        (function(){
          var HOLIDAYS = {
            '2026-01-01':'New Years Day','2026-01-19':'MLK Day','2026-02-16':'Presidents Day',
            '2026-05-25':'Memorial Day','2026-06-19':'Juneteenth','2026-07-04':'Independence Day',
            '2026-09-07':'Labor Day','2026-10-12':'Columbus Day','2026-11-11':'Veterans Day',
            '2026-11-26':'Thanksgiving','2026-11-27':'Day After Thanksgiving','2026-12-25':'Christmas',
            '2027-01-01':'New Years Day','2027-01-18':'MLK Day','2027-02-15':'Presidents Day',
            '2027-05-31':'Memorial Day','2027-06-19':'Juneteenth','2027-07-04':'Independence Day',
            '2027-09-06':'Labor Day','2027-11-25':'Thanksgiving','2027-12-25':'Christmas'
          };
          var MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
          var DAYS   = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
          var TYPE_ICONS = {reminder:'&#128276;',task:'&#9989;',meeting:'&#128197;',deadline:'&#128680;'};

          // safe localStorage
          function lsGet(k){try{return localStorage.getItem(k);}catch(e){return null;}}
          function lsSet(k,v){try{localStorage.setItem(k,v);}catch(e){}}

          var cs = {y:2026, m:8};
          var reminders = JSON.parse(lsGet('cal_reminders2')||'[]');

          function ds(y,m,d){return y+'-'+('0'+(m+1)).slice(-2)+'-'+('0'+d).slice(-2);}

          function buildCal(){
            var y=cs.y, m=cs.m;
            var now=new Date(); var ty=now.getFullYear(),tm=now.getMonth(),td=now.getDate();
            var title=MONTHS[m]+' '+y;
            document.getElementById('cal-title').textContent=title;
            document.getElementById('cal-sub').textContent=title+' \u2014 your schedule at a glance';

            var grid=document.getElementById('cal-grid');
            while(grid.children.length>7) grid.removeChild(grid.lastChild);

            var first=new Date(y,m,1).getDay();
            var days=new Date(y,m+1,0).getDate();

            for(var i=0;i<first;i++){
              var blank=document.createElement('div');blank.style.padding='8px';grid.appendChild(blank);
            }
            for(var d=1;d<=days;d++){
              var key=ds(y,m,d);
              var dow=new Date(y,m,d).getDay();
              var isToday=(y===ty&&m===tm&&d===td);
              var isHol=!!HOLIDAYS[key];
              var isWeekend=(dow===0||dow===6);
              var isWork=!isWeekend&&!isHol;
              var rems=reminders.filter(function(r){return r.date===key;});

              var cell=document.createElement('div');
              cell.style.cssText='padding:6px 2px;border-radius:6px;cursor:pointer;font-size:13px;min-height:42px;display:flex;flex-direction:column;align-items:center;gap:2px;transition:filter .1s;';

              if(isToday){
                cell.style.background='rgba(88,166,255,.18)';
                cell.style.border='1px solid var(--accent)';
                cell.style.color='var(--accent)';
              } else if(isHol){
                cell.style.background='rgba(248,81,73,.18)';
                cell.style.color='#f87171';
              } else if(isWork){
                cell.style.background='rgba(63,185,80,.1)';
                cell.style.color='var(--accent2)';
              } else {
                cell.style.color='var(--muted)';
              }

              var num=document.createElement('div');
              num.textContent=d;
              num.style.fontWeight=isToday?'700':'400';
              cell.appendChild(num);

              if(isHol||rems.length>0){
                var dots=document.createElement('div');
                dots.style.cssText='display:flex;gap:2px;justify-content:center;';
                if(isHol){var dot=document.createElement('div');dot.style.cssText='width:5px;height:5px;border-radius:50%;background:#f85149;';dots.appendChild(dot);}
                if(rems.length>0){var dot2=document.createElement('div');dot2.style.cssText='width:5px;height:5px;border-radius:50%;background:#d29922;';dots.appendChild(dot2);}
                cell.appendChild(dots);
              }

              cell.onmouseover=function(){this.style.filter='brightness(1.25)';};
              cell.onmouseout=function(){this.style.filter='';};
              (function(day,dateKey,hol,dayRems){
                cell.onclick=function(){showDetail(day,dateKey,hol,dayRems);};
              })(d,key,HOLIDAYS[key],rems);

              grid.appendChild(cell);
            }
          }

          function showDetail(day,dateKey,hol,rems){
            var dow=new Date(dateKey).getDay();
            var panel=document.getElementById('cal-day-detail');
            var title=document.getElementById('cal-detail-title');
            var body=document.getElementById('cal-detail-body');
            title.textContent=DAYS[dow]+', '+MONTHS[cs.m]+' '+day+', '+cs.y;
            var html='';
            if(hol) html+='<div style="margin-bottom:6px"><span style="background:rgba(248,81,73,.15);color:#f87171;font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px">&#127881; '+hol+'</span></div>';
            if(rems.length>0){
              html+='<div style="font-weight:600;font-size:12px;margin-bottom:4px;color:var(--text)">Reminders:</div>';
              rems.forEach(function(r){
                html+='<div style="display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid var(--border)"><span>'+TYPE_ICONS[r.type||'reminder']+'</span><span style="font-size:12px;color:var(--text)">'+r.text+'</span></div>';
              });
            }
            if(!hol&&rems.length===0) html='<span style="color:var(--muted);font-size:12px">No events for this day.</span>';
            body.innerHTML=html;
            panel.style.display='block';
          }

          document.getElementById('cal-prev').onclick=function(){cs.m--;if(cs.m<0){cs.m=11;cs.y--;}buildCal();};
          document.getElementById('cal-next').onclick=function(){cs.m++;if(cs.m>11){cs.m=0;cs.y++;}buildCal();};

          // Reminders
          function renderRems(){
            var list=document.getElementById('rem-list');
            if(reminders.length===0){list.innerHTML='<div style="color:var(--muted);font-size:13px;padding:4px 0">No reminders yet. Add one above.</div>';return;}
            var sorted=[].concat(reminders).sort(function(a,b){return a.date.localeCompare(b.date);});
            var today=new Date().toISOString().split('T')[0];
            list.innerHTML=sorted.map(function(r,i){
              var past=r.date<today;
              return '<div style="display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--surface2);border-radius:6px;border:1px solid var(--border);'+(past?'opacity:.5':'')+'">'
                +'<span style="font-size:16px">'+TYPE_ICONS[r.type||'reminder']+'</span>'
                +'<div style="flex:1"><div style="font-size:13px;color:var(--text)">'+r.text+'</div><div style="font-size:10px;color:var(--muted)">'+r.date+'</div></div>'
                +'<button onclick="calDel('+i+')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:2px 6px">&times;</button>'
                +'</div>';
            }).join('');
          }

          window.calDel=function(idx){
            var sorted=[].concat(reminders).sort(function(a,b){return a.date.localeCompare(b.date);});
            var t=sorted[idx];
            reminders=reminders.filter(function(r){return !(r.text===t.text&&r.date===t.date&&r.type===t.type);});
            lsSet('cal_reminders2',JSON.stringify(reminders));
            renderRems();buildCal();
          };

          document.getElementById('rem-add-btn').onclick=function(){
            var txt=document.getElementById('rem-text').value.trim();
            var dt=document.getElementById('rem-date').value;
            var tp=document.getElementById('rem-type').value;
            if(!txt||!dt){alert('Please enter reminder text and a date.');return;}
            reminders.push({text:txt,date:dt,type:tp});
            lsSet('cal_reminders2',JSON.stringify(reminders));
            document.getElementById('rem-text').value='';
            document.getElementById('rem-date').value='';
            renderRems();buildCal();
          };

          // Notes
          var notesEl=document.getElementById('cal-notes');
          notesEl.value=lsGet('cal_notes2')||'';
          document.getElementById('notes-save-btn').onclick=function(){
            lsSet('cal_notes2',notesEl.value);
            var msg=document.getElementById('notes-saved-msg');
            msg.style.display='inline';
            setTimeout(function(){msg.style.display='none';},2000);
          };

          buildCal();
          renderRems();
        })();
        </script>
      </div>

      """

new_html = html[:s] + NEW + html[e:]

with open(filepath, "w", encoding="utf-8") as f:
    f.write(new_html)

print("SUCCESS! File: "+str(len(new_html))+" bytes (was "+str(len(html))+")")


START = "<!-- CALENDAR PAGE -->"
END   = "<!-- PTO PAGE -->"

s = html.find(START)
e = html.find(END)
if s == -1 or e == -1:
    print(f"Markers not found s={s} e={e}")
    exit(1)

print(f"Calendar block: chars {s}..{e}")

NEW_CALENDAR = """<!-- CALENDAR PAGE -->
      <div class="page" id="page-calendar">
        <div class="page-header">
          <h1>Calendar</h1>
          <p id="cal-subtitle">Loading...</p>
        </div>

        <!-- Calendar card -->
        <div class="card" style="margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
            <button id="cal-prev" style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 14px;color:var(--text);cursor:pointer;font-family:inherit;font-size:13px">&#8592; Prev</button>
            <div id="cal-title" style="font-family:'Syne',sans-serif;font-size:16px;font-weight:700"></div>
            <button id="cal-next" style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 14px;color:var(--text);cursor:pointer;font-family:inherit;font-size:13px">Next &#8594;</button>
          </div>
          <div id="cal-grid" style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px;text-align:center">
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Sun</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Mon</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Tue</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Wed</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Thu</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Fri</div>
            <div style="font-size:11px;color:var(--muted);padding:6px;font-weight:600">Sat</div>
          </div>
          <!-- Day detail panel (shown when a day is clicked) -->
          <div id="cal-day-panel" style="display:none;margin-top:14px;padding:14px;background:var(--surface2);border-radius:8px;border:1px solid var(--border)">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
              <div id="cal-panel-title" style="font-weight:600;font-size:14px"></div>
              <button onclick="document.getElementById('cal-day-panel').style.display='none'" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px">&#x2715;</button>
            </div>
            <div id="cal-panel-badges" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px"></div>
            <div id="cal-panel-events" style="font-size:12px;color:var(--muted);margin-bottom:4px"></div>
          </div>
          <div style="display:flex;gap:16px;margin-top:14px;font-size:12px;color:var(--muted);flex-wrap:wrap">
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(88,166,255,.3);margin-right:4px"></span>Today</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(63,185,80,.2);margin-right:4px"></span>Work Day</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--surface2);margin-right:4px"></span>Day Off</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(248,81,73,.25);margin-right:4px"></span>Holiday</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(210,153,34,.25);margin-right:4px"></span>Task / Reminder</span>
          </div>
        </div>

        <!-- Daily Reminders & Notes -->
        <div class="grid-2" style="margin-bottom:0">
          <div class="card">
            <div class="card-title">&#128203; Daily Reminders</div>
            <div style="margin-bottom:10px">
              <div style="display:flex;gap:8px;margin-bottom:8px">
                <input id="rem-text" class="ai-input" placeholder="Add a reminder..." style="flex:1;font-size:13px">
                <input id="rem-date" type="date" class="ai-input" style="width:130px;font-size:13px">
                <button onclick="calAddReminder()" style="background:var(--accent);color:#fff;border:none;border-radius:6px;padding:7px 14px;cursor:pointer;font-size:13px;font-family:inherit;font-weight:500;white-space:nowrap">+ Add</button>
              </div>
            </div>
            <div id="rem-list" style="display:flex;flex-direction:column;gap:6px;max-height:260px;overflow-y:auto">
              <!-- Reminders rendered here -->
            </div>
          </div>

          <div class="card">
            <div class="card-title">&#128221; Notes Pad</div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Personal notes — visible only to you</div>
            <textarea id="cal-notes" placeholder="Write your daily notes, to-dos, or anything you want to remember..." style="width:100%;min-height:180px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;color:var(--text);font-family:inherit;font-size:13px;resize:vertical;outline:none;line-height:1.5"></textarea>
            <div style="display:flex;gap:8px;margin-top:8px">
              <button onclick="calSaveNotes()" style="background:var(--accent2);color:var(--navy,#0d1117);border:none;border-radius:6px;padding:7px 16px;cursor:pointer;font-size:12px;font-family:inherit;font-weight:600">Save Notes</button>
              <span id="notes-saved" style="display:none;font-size:11px;color:var(--accent2);line-height:32px">&#10003; Saved</span>
            </div>
          </div>
        </div>

        <!-- Calendar JS -->
        <script>
        (function(){
          // ── US Federal Holidays ──
          var HOLIDAYS = {
            '2026-01-01':'New Year\'s Day','2026-01-19':'MLK Day','2026-02-16':'Presidents\' Day',
            '2026-05-25':'Memorial Day','2026-06-19':'Juneteenth','2026-07-04':'Independence Day',
            '2026-09-07':'Labor Day','2026-10-12':'Columbus Day','2026-11-11':'Veterans Day',
            '2026-11-26':'Thanksgiving','2026-11-27':'Day after Thanksgiving','2026-12-25':'Christmas Day',
            '2027-01-01':'New Year\'s Day','2027-01-18':'MLK Day','2027-02-15':'Presidents\' Day',
            '2027-05-31':'Memorial Day','2027-06-19':'Juneteenth','2027-07-04':'Independence Day',
            '2027-09-06':'Labor Day','2027-11-25':'Thanksgiving','2027-12-25':'Christmas Day'
          };

          var calState = { year:2026, month:8 }; // 0-indexed, 8=Sep
          var reminders = JSON.parse(localStorage.getItem('cal_reminders')||'[]');
          var MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

          function dateStr(y,m,d){ return y+'-'+String(m+1).padStart(2,'0')+'-'+String(d).padStart(2,'0'); }
          function isWeekend(dayOfWeek){ return dayOfWeek===0||dayOfWeek===6; }

          function renderCal(){
            var y=calState.year, m=calState.month;
            var today=new Date(); var ty=today.getFullYear(),tm=today.getMonth(),td=today.getDate();
            var firstDay=new Date(y,m,1).getDay();
            var daysInMonth=new Date(y,m+1,0).getDate();
            var title=MONTHS[m]+' '+y;
            document.getElementById('cal-title').textContent=title;
            document.getElementById('cal-subtitle').textContent=title+' \u2014 your schedule at a glance';

            var grid=document.getElementById('cal-grid');
            // Remove all cells after header row (first 7 divs)
            while(grid.children.length>7) grid.removeChild(grid.lastChild);

            // Blank cells
            for(var i=0;i<firstDay;i++){var b=document.createElement('div');b.style.padding='8px';grid.appendChild(b);}

            for(var d=1;d<=daysInMonth;d++){
              var ds=dateStr(y,m,d);
              var dow=new Date(y,m,d).getDay();
              var isToday=(y===ty&&m===tm&&d===td);
              var isHol=!!HOLIDAYS[ds];
              var hasRem=reminders.some(function(r){return r.date===ds;});
              var isWork=!isWeekend(dow)&&!isHol;

              var cell=document.createElement('div');
              cell.style.padding='6px 4px';
              cell.style.borderRadius='6px';
              cell.style.cursor='pointer';
              cell.style.position='relative';
              cell.style.fontSize='13px';
              cell.style.transition='background .1s';
              cell.style.minHeight='38px';
              cell.style.display='flex';
              cell.style.flexDirection='column';
              cell.style.alignItems='center';
              cell.style.gap='2px';

              var numEl=document.createElement('div');
              numEl.textContent=d;
              numEl.style.fontWeight=isToday?'700':'400';
              cell.appendChild(numEl);

              // Dot row for indicators
              var dots=document.createElement('div');
              dots.style.display='flex';dots.style.gap='2px';dots.style.justifyContent='center';

              if(isHol){
                cell.style.background='rgba(248,81,73,.18)';
                cell.style.color='#f87171';
                var hd=document.createElement('div');hd.style.cssText='width:5px;height:5px;border-radius:50%;background:#f85149';dots.appendChild(hd);
              } else if(isToday){
                cell.style.background='rgba(88,166,255,.18)';
                cell.style.border='1px solid var(--accent)';
                cell.style.color='var(--accent)';
              } else if(isWork){
                cell.style.background='rgba(63,185,80,.1)';
                cell.style.color='var(--accent2)';
              } else {
                cell.style.color='var(--muted)';
              }

              if(hasRem){
                var rd=document.createElement('div');rd.style.cssText='width:5px;height:5px;border-radius:50%;background:#d29922';dots.appendChild(rd);
              }
              if(dots.children.length>0) cell.appendChild(dots);

              (function(day,dateString,holiday,rems){
                cell.onmouseover=function(){if(!isToday&&!isHol)cell.style.filter='brightness(1.2)';};
                cell.onmouseout=function(){cell.style.filter='';};
                cell.onclick=function(){ showDayPanel(day,dateString,holiday,rems); };
              })(d,ds,HOLIDAYS[ds],reminders.filter(function(r){return r.date===ds;}));

              cell.appendChild(dots);
              grid.appendChild(cell);
            }
          }

          function showDayPanel(day,ds,holiday,rems){
            var panel=document.getElementById('cal-day-panel');
            var y=calState.year,m=calState.month;
            var dow=new Date(y,m,day).getDay();
            var days=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
            document.getElementById('cal-panel-title').textContent=days[dow]+', '+MONTHS[m]+' '+day+', '+y;
            var badges=document.getElementById('cal-panel-badges');
            badges.innerHTML='';
            if(holiday){
              var hb=document.createElement('span');
              hb.textContent='&#127881; '+holiday;
              hb.style.cssText='background:rgba(248,81,73,.15);color:#f87171;font-size:11px;font-weight:600;padding:3px 8px;border-radius:12px';
              badges.appendChild(hb);
            }
            if(dow===0||dow===6){
              var wb=document.createElement('span');wb.textContent='Day Off';
              wb.style.cssText='background:rgba(139,148,158,.12);color:var(--muted);font-size:11px;font-weight:600;padding:3px 8px;border-radius:12px';
              badges.appendChild(wb);
            } else if(!holiday){
              var wkb=document.createElement('span');wkb.textContent='Work Day';
              wkb.style.cssText='background:rgba(63,185,80,.12);color:var(--accent2);font-size:11px;font-weight:600;padding:3px 8px;border-radius:12px';
              badges.appendChild(wkb);
            }
            var evDiv=document.getElementById('cal-panel-events');
            if(rems.length>0){
              evDiv.innerHTML='<div style="font-weight:500;color:var(--text);margin-bottom:4px;font-size:12px">Reminders:</div>'+rems.map(function(r){return '<div style="display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid var(--border)"><span style="font-size:16px">'+r.emoji+'</span><span style="font-size:12px;color:var(--text)">'+r.text+'</span></div>';}).join('');
            } else {
              evDiv.innerHTML='<div style="color:var(--muted);font-size:12px">No reminders for this day.</div>';
            }
            panel.style.display='block';
          }

          document.getElementById('cal-prev').onclick=function(){
            calState.month--;if(calState.month<0){calState.month=11;calState.year--;}renderCal();
          };
          document.getElementById('cal-next').onclick=function(){
            calState.month++;if(calState.month>11){calState.month=0;calState.year++;}renderCal();
          };

          // Reminders
          var EMOJIS=['&#128203;','&#9989;','&#128276;','&#127775;','&#128680;'];
          function renderReminders(){
            var list=document.getElementById('rem-list');
            if(reminders.length===0){
              list.innerHTML='<div style="color:var(--muted);font-size:13px;padding:8px 0">No reminders yet. Add one above.</div>';
              return;
            }
            var sorted=[].concat(reminders).sort(function(a,b){return a.date.localeCompare(b.date);});
            list.innerHTML=sorted.map(function(r,i){
              var today=new Date().toISOString().split('T')[0];
              var isPast=r.date<today;
              return '<div style="display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--surface2);border-radius:6px;border:1px solid var(--border)'+(isPast?';opacity:.55':'')+'">'
                +'<span style="font-size:16px">'+r.emoji+'</span>'
                +'<div style="flex:1"><div style="font-size:13px;color:var(--text)">'+r.text+'</div><div style="font-size:10px;color:var(--muted)">'+r.date+'</div></div>'
                +'<button onclick="calDelReminder('+i+')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:2px 6px" title="Delete">&#x2715;</button>'
                +'</div>';
            }).join('');
          }

          window.calAddReminder=function(){
            var txt=document.getElementById('rem-text').value.trim();
            var dt=document.getElementById('rem-date').value;
            if(!txt||!dt){alert('Please enter both a reminder text and a date.');return;}
            reminders.push({text:txt,date:dt,emoji:EMOJIS[Math.floor(Math.random()*EMOJIS.length)]});
            localStorage.setItem('cal_reminders',JSON.stringify(reminders));
            document.getElementById('rem-text').value='';
            document.getElementById('rem-date').value='';
            renderReminders();renderCal();
          };

          window.calDelReminder=function(idx){
            var sorted=[].concat(reminders).sort(function(a,b){return a.date.localeCompare(b.date);});
            var target=sorted[idx];
            reminders=reminders.filter(function(r){return !(r.text===target.text&&r.date===target.date);});
            localStorage.setItem('cal_reminders',JSON.stringify(reminders));
            renderReminders();renderCal();
          };

          // Notes
          var notesKey='cal_notes';
          var notesEl=document.getElementById('cal-notes');
          notesEl.value=localStorage.getItem(notesKey)||'';
          window.calSaveNotes=function(){
            localStorage.setItem(notesKey,notesEl.value);
            var sv=document.getElementById('notes-saved');
            sv.style.display='inline';
            setTimeout(function(){sv.style.display='none';},2000);
          };
          notesEl.addEventListener('input',function(){document.getElementById('notes-saved').style.display='none';});

          // Init
          renderCal();
          renderReminders();
        })();
        </script>
      </div>

      """

new_html = html[:s] + NEW_CALENDAR + html[e:]

with open(filepath, "w", encoding="utf-8") as f:
    f.write(new_html)

print(f"SUCCESS! Calendar updated. File: {len(new_html)} bytes (was {len(html)})")


# Find the exact pay page block using reliable bookmarks
start_marker = "<!-- PAY & BENEFITS PAGE -->"
end_marker   = "<!-- TASKS PAGE -->"

s = html.find(start_marker)
e = html.find(end_marker)

if s == -1 or e == -1:
    print(f"ERROR: markers not found. s={s} e={e}")
    exit(1)

print(f"Found block at chars {s}..{e}")

# Preserve the leading whitespace before the start marker
line_start = html.rfind('\n', 0, s) + 1
leading    = html[line_start:s]

REPLACEMENT = leading + """<!-- PAY & BENEFITS PAGE -->
""" + leading[:-0] + """<div class="page" id="page-pay">
""" + leading + """  <div class="page-header">
""" + leading + """    <h1>Pay &amp; Benefits</h1>
""" + leading + """    <p>Pay stubs, tax forms, and benefit details</p>
""" + leading + """  </div>
""" + leading + """  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
""" + leading + """    <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Annual Gross</div><div style="font-size:21px;font-weight:700;color:var(--accent2);font-family:monospace">$62,400</div><div style="font-size:11px;color:var(--muted);margin-top:3px">$5,200 / month</div></div>
""" + leading + """    <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Deductions</div><div style="font-size:21px;font-weight:700;color:var(--danger);font-family:monospace">$14,820</div><div style="font-size:11px;color:var(--muted);margin-top:3px">$1,235 / month</div></div>
""" + leading + """    <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Net Take-Home</div><div style="font-size:21px;font-weight:700;color:#d29922;font-family:monospace">$47,580</div><div style="font-size:11px;color:var(--muted);margin-top:3px">$3,965 / month</div></div>
""" + leading + """    <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Tax Rate</div><div style="font-size:21px;font-weight:700;color:var(--accent);font-family:monospace">23.7%</div><div style="font-size:11px;color:var(--muted);margin-top:3px">Fed + State + FICA</div></div>
""" + leading + """  </div>
""" + leading + """  <div class="grid-2" style="margin-bottom:16px">
""" + leading + """    <div class="card"><div class="card-title">Monthly pay vs. deductions</div><canvas id="pay-bar-chart" height="220"></canvas></div>
""" + leading + """    <div class="card"><div class="card-title">Benefits breakdown</div>
""" + leading + """      <div style="position:relative;height:195px;display:flex;align-items:center;justify-content:center"><canvas id="pay-donut-chart"></canvas><div style="position:absolute;text-align:center;pointer-events:none"><div style="font-size:17px;font-weight:700;color:var(--accent2);font-family:monospace">$1,235</div><div style="font-size:11px;color:var(--muted)">/ month</div></div></div>
""" + leading + """      <div style="display:flex;flex-direction:column;gap:6px;margin-top:10px">
""" + leading + """        <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:#388bfd;flex-shrink:0"></div><span style="color:var(--muted);flex:1">Federal tax</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$468</span></div>
""" + leading + """        <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:#bc8cff;flex-shrink:0"></div><span style="color:var(--muted);flex:1">State tax (AZ)</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$156</span></div>
""" + leading + """        <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:#d29922;flex-shrink:0"></div><span style="color:var(--muted);flex:1">FICA</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$378</span></div>
""" + leading + """        <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:var(--accent2);flex-shrink:0"></div><span style="color:var(--muted);flex:1">Health insurance</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$145</span></div>
""" + leading + """        <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:var(--danger);flex-shrink:0"></div><span style="color:var(--muted);flex:1">401(k)</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$88</span></div>
""" + leading + """      </div>
""" + leading + """    </div>
""" + leading + """  </div>
""" + leading + """  <div class="grid-2" style="margin-bottom:16px">
""" + leading + """    <div class="card">
""" + leading + """      <div class="card-title">Latest pay stub \u2014 Aug 31, 2026</div>
""" + leading + """      <div class="pay-row"><span>Regular Pay (80h)</span><span>$2,400.00</span></div>
""" + leading + """      <div class="pay-row"><span>Overtime (4h)</span><span>$180.00</span></div>
""" + leading + """      <div class="pay-row"><span>Federal Tax</span><span style="color:var(--danger)">\u2013$312.00</span></div>
""" + leading + """      <div class="pay-row"><span>State Tax (AZ)</span><span style="color:var(--danger)">\u2013$68.00</span></div>
""" + leading + """      <div class="pay-row"><span>Health Insurance</span><span style="color:var(--danger)">\u2013$124.00</span></div>
""" + leading + """      <div class="pay-row"><span>401(k) 4%</span><span style="color:var(--danger)">\u2013$96.00</span></div>
""" + leading + """      <div class="pay-row total"><span>Net Pay</span><span style="color:var(--accent2)">$1,980.00</span></div>
""" + leading + """      <button class="btn-primary" style="margin-top:14px" onclick="payDlPDF()">Download PDF</button>
""" + leading + """    </div>
""" + leading + """    <div>
""" + leading + """      <div class="card">
""" + leading + """        <div class="card-title">Benefits</div>
""" + leading + """        <div class="pay-row"><span>Health Plan</span><span class="tag tag-green">Blue Cross PPO</span></div>
""" + leading + """        <div class="pay-row"><span>Dental</span><span class="tag tag-green">Enrolled</span></div>
""" + leading + """        <div class="pay-row"><span>Vision</span><span class="tag tag-green">Enrolled</span></div>
""" + leading + """        <div class="pay-row"><span>401(k)</span><span class="tag tag-blue">4% match</span></div>
""" + leading + """        <div class="pay-row"><span>FSA Balance</span><span style="color:var(--accent2)">$842.50</span></div>
""" + leading + """      </div>
""" + leading + """      <div class="card" style="margin-top:0">
""" + leading + """        <div class="card-title">Tax Forms</div>
""" + leading + """        <div class="pay-row"><span>W-2 2025</span><span style="cursor:pointer;color:var(--accent)" onclick="payDlW2(2025)">Download</span></div>
""" + leading + """        <div class="pay-row"><span>W-2 2024</span><span style="cursor:pointer;color:var(--accent)" onclick="payDlW2(2024)">Download</span></div>
""" + leading + """      </div>
""" + leading + """    </div>
""" + leading + """  </div>
""" + leading + """  <div class="card" style="margin-bottom:16px">
""" + leading + """    <div class="card-title">Hourly rate calculator</div>
""" + leading + """    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px">
""" + leading + """      <div><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Annual salary</label><input class="ai-input" type="number" id="pay-sal" value="62400" oninput="payCalcHr()" style="width:100%"></div>
""" + leading + """      <div><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Hours per week</label><input class="ai-input" type="number" id="pay-hrs" value="40" oninput="payCalcHr()" style="width:100%"></div>
""" + leading + """      <div><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Weeks per year</label><input class="ai-input" type="number" id="pay-wks" value="52" oninput="payCalcHr()" style="width:100%"></div>
""" + leading + """    </div>
""" + leading + """    <div style="display:flex;flex-wrap:wrap;gap:20px;background:rgba(56,139,253,.07);border:1px solid rgba(56,139,253,.2);border-radius:6px;padding:14px 18px;margin-bottom:14px">
""" + leading + """      <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Hourly rate</div><div id="pay-r-hr" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$30.00</div></div>
""" + leading + """      <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Daily (8h)</div><div id="pay-r-day" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$240.00</div></div>
""" + leading + """      <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Weekly</div><div id="pay-r-wk" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$1,200.00</div></div>
""" + leading + """      <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Bi-weekly</div><div id="pay-r-biwk" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$2,400.00</div></div>
""" + leading + """      <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Monthly</div><div id="pay-r-mo" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$5,200.00</div></div>
""" + leading + """    </div>
""" + leading + """    <canvas id="pay-hr-bar" height="160"></canvas>
""" + leading + """  </div>
""" + leading + """  <div class="card" style="margin-bottom:16px">
""" + leading + """    <div class="card-title">Tax document vault</div>
""" + leading + """    <div id="pay-docs-grid" style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px">
""" + leading + """      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128203;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">W-2 Form \u2014 2025</div><div style="font-size:11px;color:var(--muted)">Added Jan 31, 2026</div></div>
""" + leading + """      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128203;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">W-2 Form \u2014 2024</div><div style="font-size:11px;color:var(--muted)">Added Feb 3, 2025</div></div>
""" + leading + """      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(210,153,34,.15);color:#d29922">Pending</span><div style="font-size:20px;margin-bottom:6px">&#128196;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">1099-NEC \u2014 2025</div><div style="font-size:11px;color:var(--muted)">Awaiting from payer</div></div>
""" + leading + """      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128202;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">Tax deductions log</div><div style="font-size:11px;color:var(--muted)">14 entries \u00b7 FY 2025</div></div>
""" + leading + """      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(139,148,158,.12);color:var(--muted)">Not uploaded</span><div style="font-size:20px;margin-bottom:6px">&#128193;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">1040 Return \u2014 2025</div><div style="font-size:11px;color:var(--muted)">Click to upload</div></div>
""" + leading + """      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#10084;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">Benefits statement</div><div style="font-size:11px;color:var(--muted)">Enrollment 2025</div></div>
""" + leading + """    </div>
""" + leading + """    <div onclick="document.getElementById('pay-file-input').click()" style="border:2px dashed var(--border);border-radius:6px;padding:18px;text-align:center;cursor:pointer" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
""" + leading + """      <div style="font-size:11px;color:var(--muted)"><span style="color:var(--accent);font-weight:500">Click to upload</span> a tax document \u2014 W-2 \u00b7 1099 \u00b7 1040 \u00b7 PDF \u00b7 max 25MB</div>
""" + leading + """    </div>
""" + leading + """    <input type="file" id="pay-file-input" style="display:none" accept=".pdf,.png,.jpg,.jpeg" onchange="payAddDoc(event)">
""" + leading + """  </div>
""" + leading + """  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px">
""" + leading + """    <button class="btn-primary" onclick="payDlPDF()">Download PDF Report</button>
""" + leading + """    <button class="btn-secondary" onclick="payOpenEmail()">Email PDF Report</button>
""" + leading + """  </div>
""" + leading + """</div>
""" + leading + """<div id="pay-email-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center"><div style="background:var(--surface1);border:1px solid var(--border);border-radius:10px;padding:24px;width:440px;max-width:95vw"><div style="font-size:16px;font-weight:700;margin-bottom:18px">Email PDF Report</div><div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Recipient email</label><input class="ai-input" type="email" id="pay-m-to" placeholder="employee@company.com" style="width:100%"></div><div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Your name</label><input class="ai-input" type="text" id="pay-m-name" placeholder="Jamie Vavro" style="width:100%"></div><div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Report type</label><select class="ai-input" id="pay-m-report" style="width:100%"><option>Pay &amp; benefits summary</option><option>Hourly breakdown</option><option>Tax deductions report</option><option>Full package</option></select></div><div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Note (optional)</label><textarea class="ai-input" id="pay-m-note" placeholder="Add a note..." style="width:100%;resize:vertical;min-height:70px"></textarea></div><div id="pay-m-status" style="display:none;font-size:12px;padding:8px 12px;border-radius:6px;margin-bottom:10px"></div><div style="display:flex;gap:10px;justify-content:flex-end"><button class="btn-secondary" onclick="payCloseEmail()">Cancel</button><button class="btn-primary" onclick="paySendEmail()">Send Report</button></div></div></div>
""" + leading + """<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
""" + leading + """<script>
""" + leading + """var _pBC=null,_pDC=null,_pHC=null;
""" + leading + """function _pInit(){if(!window.Chart)return;if(!_pBC){var c=document.getElementById('pay-bar-chart');if(c){_pBC=new Chart(c.getContext('2d'),{type:'bar',data:{labels:['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],datasets:[{label:'Gross',data:Array(12).fill(5200),backgroundColor:'rgba(63,185,80,.65)',borderRadius:4},{label:'Net',data:Array(12).fill(3965),backgroundColor:'rgba(56,139,253,.65)',borderRadius:4},{label:'Deductions',data:Array(12).fill(1235),backgroundColor:'rgba(248,81,73,.65)',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{labels:{color:'#8b949e',font:{size:11}}}},scales:{x:{ticks:{color:'#8b949e',font:{size:11}},grid:{color:'rgba(255,255,255,.04)'}},y:{ticks:{color:'#8b949e',font:{size:11},callback:function(v){return'$'+v.toLocaleString();}},grid:{color:'rgba(255,255,255,.04)'}}}}});}}if(!_pDC){var d=document.getElementById('pay-donut-chart');if(d){_pDC=new Chart(d.getContext('2d'),{type:'doughnut',data:{datasets:[{data:[468,156,378,145,88],backgroundColor:['#388bfd','#bc8cff','#d29922','#3fb950','#f85149'],borderWidth:0,hoverOffset:5}]},options:{responsive:true,maintainAspectRatio:false,cutout:'68%',plugins:{legend:{display:false}}}});}} _pHrBar();}
""" + leading + """function _pHrBar(){var sal=parseFloat((document.getElementById('pay-sal')||{value:62400}).value)||62400,hrs=parseFloat((document.getElementById('pay-hrs')||{value:40}).value)||40,wks=parseFloat((document.getElementById('pay-wks')||{value:52}).value)||52,g=sal/(hrs*wks),vals=[g,g*.09,g*.03,g*.0765,g*.028,g*.017,g*.763].map(function(v){return+v.toFixed(2);});if(_pHC)_pHC.destroy();var hc=document.getElementById('pay-hr-bar');if(!hc||!window.Chart)return;_pHC=new Chart(hc.getContext('2d'),{type:'bar',data:{labels:['Gross/hr','Federal','State','FICA','Health','401(k)','Net/hr'],datasets:[{data:vals,backgroundColor:['#3fb950','#388bfd','#bc8cff','#d29922','#f85149','#e3b341','#3fb950'],borderRadius:4}]},options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8b949e',font:{size:11}},grid:{color:'rgba(255,255,255,.04)'}},y:{ticks:{color:'#8b949e',font:{size:11},callback:function(v){return'$'+v.toFixed(2);}},grid:{color:'rgba(255,255,255,.04)'}}}}});}
""" + leading + """var _pf=function(n){return'$'+n.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});};
""" + leading + """function payCalcHr(){var sal=parseFloat(document.getElementById('pay-sal').value)||0,hrs=parseFloat(document.getElementById('pay-hrs').value)||40,wks=parseFloat(document.getElementById('pay-wks').value)||52,hr=sal/(hrs*wks);document.getElementById('pay-r-hr').textContent=_pf(hr);document.getElementById('pay-r-day').textContent=_pf(hr*8);document.getElementById('pay-r-wk').textContent=_pf(hr*hrs);document.getElementById('pay-r-biwk').textContent=_pf(hr*hrs*2);document.getElementById('pay-r-mo').textContent=_pf(sal/12);_pHrBar();}
""" + leading + """function payOpenEmail(){var m=document.getElementById('pay-email-modal');if(m)m.style.display='flex';}
""" + leading + """function payCloseEmail(){var m=document.getElementById('pay-email-modal');if(m)m.style.display='none';}
""" + leading + """async function paySendEmail(){var to=document.getElementById('pay-m-to').value.trim(),name=document.getElementById('pay-m-name').value.trim(),report=document.getElementById('pay-m-report').value,note=document.getElementById('pay-m-note').value.trim(),st=document.getElementById('pay-m-status');if(!to||!name){st.textContent='Fill in recipient email and name.';st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(248,81,73,.1);color:var(--danger);border:1px solid rgba(248,81,73,.2)';return;}st.textContent='Sending via AI-Prowler...';st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(56,139,253,.08);color:var(--accent);border:1px solid rgba(56,139,253,.2)';try{var res=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:'claude-sonnet-4-6',max_tokens:1000,mcp_servers:[{type:'url',url:'https://ap-david-vavro1-00303282.ai-prowler.com/mcp',name:'ai-prowler'}],messages:[{role:'user',content:'Use send_email tool. To: '+to+' | Name: '+name+' | Report: '+report+' | Note: '+(note||'none')+'. Subject: Your '+report+' - AI-Prowler HR. Body: Gross $62,400 Net $47,580 Tax 23.7%.'}]})});var data=await res.json(),txt=(data.content||[]).map(function(b){return b.text||(b.content&&b.content[0]&&b.content[0].text)||'';}).join(' ').toLowerCase();st.textContent=(txt.includes('sent')||txt.includes('success'))?'Sent to '+to:'Delivered to AI-Prowler for '+to;st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(63,185,80,.1);color:var(--accent2);border:1px solid rgba(63,185,80,.2)';}catch(e){st.textContent='Could not reach AI-Prowler email.';st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(248,81,73,.1);color:var(--danger);border:1px solid rgba(248,81,73,.2)';}}
""" + leading + """function payDlPDF(){var b=new Blob(['PAY & BENEFITS\\nGross $62,400 Net $47,580 Tax 23.7% Hourly $30.00\\nPay Stub Aug 31: Reg $2,400 OT $180 Fed -$312 State -$68 Health -$124 401k -$96 Net $1,980\\nBenefits: Blue Cross PPO Dental Vision 401k 4% FSA $842.50'],{type:'text/plain'});var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='PayBenefits_'+new Date().toISOString().split('T')[0]+'.txt';a.click();}
""" + leading + """function payDlW2(yr){var b=new Blob(['W-2 '+yr+'\\nEmployee: Jamie Vavro | Employer: AI-Prowler\\nWages: $62,400 Federal: $5,616 SS: $3,869 Medicare: $905'],{type:'text/plain'});var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='W2_'+yr+'.txt';a.click();}
""" + leading + """function payAddDoc(e){var file=e.target.files[0];if(!file)return;var grid=document.getElementById('pay-docs-grid'),d=document.createElement('div');d.style.cssText='background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative';d.innerHTML='<span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128196;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">'+file.name+'</div><div style="font-size:11px;color:var(--muted)">Uploaded today</div>';grid.appendChild(d);}
""" + leading + """document.addEventListener('click',function(e){if(e.target&&e.target.id==='pay-email-modal')payCloseEmail();});
""" + leading + """(function(){var _n=window.navigate;window.navigate=function(el,pg,t){if(typeof _n==='function')_n(el,pg,t);if(pg==='pay')setTimeout(_pInit,200);};if(document.getElementById('page-pay')&&document.getElementById('page-pay').classList.contains('active'))setTimeout(_pInit,400);})();
""" + leading + """</script>
"""

# Build new HTML: everything before start marker + replacement + everything from end marker
new_html = html[:line_start] + REPLACEMENT + html[e:]

with open(dest, "w", encoding="utf-8") as f:
    f.write(new_html)

print(f"SUCCESS! File written: {len(new_html)} bytes")
print(f"Old size: {len(html)} | New size: {len(new_html)} | Delta: {len(new_html)-len(html)}")


with open(dest, "r", encoding="utf-8") as f:
    html = f.read()

OLD = """        <!-- PAY & BENEFITS PAGE -->
        <div class="page" id="page-pay">
          <div class="page-header">
            <h1>Pay & Benefits</h1>
            <p>Pay stubs, tax forms, and benefit details</p>
          </div>
          <div class="grid-2">
            <div class="card">
              <div class="card-title">Latest Pay Stub \u2014 Aug 31, 2026</div>
              <div class="pay-row"><span>Regular Pay (80h)</span><span>$2,400.00</span></div>
              <div class="pay-row"><span>Overtime (4h)</span><span>$180.00</span></div>
              <div class="pay-row"><span>Federal Tax</span><span style="color:var(--danger)">\u2013$312.00</span></div>
              <div class="pay-row"><span>State Tax (AZ)</span><span style="color:var(--danger)">\u2013$68.00</span></div>
              <div class="pay-row"><span>Health Insurance</span><span style="color:var(--danger)">\u2013$124.00</span></div>
              <div class="pay-row"><span>401(k) 4%</span><span style="color:var(--danger)">\u2013$96.00</span></div>
              <div class="pay-row total"><span>Net Pay</span><span style="color:var(--accent2)">$1,980.00</span></div>
              <button class="btn-primary" style="margin-top:14px">Download PDF</button>
            </div>
            <div>
              <div class="card">
                <div class="card-title">Benefits</div>
                <div class="pay-row"><span>Health Plan</span><span class="tag tag-green">Blue Cross PPO</span></div>
                <div class="pay-row"><span>Dental</span><span class="tag tag-green">Enrolled</span></div>
                <div class="pay-row"><span>Vision</span><span class="tag tag-green">Enrolled</span></div>
                <div class="pay-row"><span>401(k)</span><span class="tag tag-blue">4% match</span></div>
                <div class="pay-row"><span>FSA Balance</span><span style="color:var(--accent2)">$842.50</span></div>
              </div>
              <div class="card" style="margin-top:0">
                <div class="card-title">Tax Forms</div>
                <div class="pay-row"><span>W-2 2025</span><span style="cursor:pointer;color:var(--accent)">Download</span></div>
                <div class="pay-row"><span>W-2 2024</span><span style="cursor:pointer;color:var(--accent)">Download</span></div>
              </div>
            </div>
          </div>
        </div>

        <!-- TASKS PAGE -->"""

NEW = """        <!-- PAY & BENEFITS PAGE -->
        <div class="page" id="page-pay">
          <div class="page-header">
            <h1>Pay &amp; Benefits</h1>
            <p>Pay stubs, tax forms, and benefit details</p>
          </div>

          <!-- Stat cards -->
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
            <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Annual Gross</div><div style="font-size:21px;font-weight:700;color:var(--accent2);font-family:monospace">$62,400</div><div style="font-size:11px;color:var(--muted);margin-top:3px">$5,200 / month</div></div>
            <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Deductions</div><div style="font-size:21px;font-weight:700;color:var(--danger);font-family:monospace">$14,820</div><div style="font-size:11px;color:var(--muted);margin-top:3px">$1,235 / month</div></div>
            <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Net Take-Home</div><div style="font-size:21px;font-weight:700;color:#d29922;font-family:monospace">$47,580</div><div style="font-size:11px;color:var(--muted);margin-top:3px">$3,965 / month</div></div>
            <div class="card" style="padding:14px 16px"><div style="font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Tax Rate</div><div style="font-size:21px;font-weight:700;color:var(--accent);font-family:monospace">23.7%</div><div style="font-size:11px;color:var(--muted);margin-top:3px">Fed + State + FICA</div></div>
          </div>

          <!-- Charts -->
          <div class="grid-2" style="margin-bottom:16px">
            <div class="card">
              <div class="card-title">Monthly pay vs. deductions</div>
              <canvas id="pay-bar-chart" height="220"></canvas>
            </div>
            <div class="card">
              <div class="card-title">Benefits breakdown</div>
              <div style="position:relative;height:195px;display:flex;align-items:center;justify-content:center">
                <canvas id="pay-donut-chart"></canvas>
                <div style="position:absolute;text-align:center;pointer-events:none"><div style="font-size:17px;font-weight:700;color:var(--accent2);font-family:monospace">$1,235</div><div style="font-size:11px;color:var(--muted)">/ month</div></div>
              </div>
              <div style="display:flex;flex-direction:column;gap:6px;margin-top:10px">
                <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:#388bfd;flex-shrink:0"></div><span style="color:var(--muted);flex:1">Federal tax</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$468</span></div>
                <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:#bc8cff;flex-shrink:0"></div><span style="color:var(--muted);flex:1">State tax (AZ)</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$156</span></div>
                <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:#d29922;flex-shrink:0"></div><span style="color:var(--muted);flex:1">FICA</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$378</span></div>
                <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:var(--accent2);flex-shrink:0"></div><span style="color:var(--muted);flex:1">Health insurance</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$145</span></div>
                <div style="display:flex;align-items:center;gap:8px;font-size:12px"><div style="width:8px;height:8px;border-radius:50%;background:var(--danger);flex-shrink:0"></div><span style="color:var(--muted);flex:1">401(k)</span><span style="font-family:monospace;font-size:11px;color:var(--danger)">$88</span></div>
              </div>
            </div>
          </div>

          <!-- Pay stub + benefits -->
          <div class="grid-2" style="margin-bottom:16px">
            <div class="card">
              <div class="card-title">Latest pay stub &mdash; Aug 31, 2026</div>
              <div class="pay-row"><span>Regular Pay (80h)</span><span>$2,400.00</span></div>
              <div class="pay-row"><span>Overtime (4h)</span><span>$180.00</span></div>
              <div class="pay-row"><span>Federal Tax</span><span style="color:var(--danger)">&ndash;$312.00</span></div>
              <div class="pay-row"><span>State Tax (AZ)</span><span style="color:var(--danger)">&ndash;$68.00</span></div>
              <div class="pay-row"><span>Health Insurance</span><span style="color:var(--danger)">&ndash;$124.00</span></div>
              <div class="pay-row"><span>401(k) 4%</span><span style="color:var(--danger)">&ndash;$96.00</span></div>
              <div class="pay-row total"><span>Net Pay</span><span style="color:var(--accent2)">$1,980.00</span></div>
              <button class="btn-primary" style="margin-top:14px" onclick="payDlPDF()">Download PDF</button>
            </div>
            <div>
              <div class="card">
                <div class="card-title">Benefits</div>
                <div class="pay-row"><span>Health Plan</span><span class="tag tag-green">Blue Cross PPO</span></div>
                <div class="pay-row"><span>Dental</span><span class="tag tag-green">Enrolled</span></div>
                <div class="pay-row"><span>Vision</span><span class="tag tag-green">Enrolled</span></div>
                <div class="pay-row"><span>401(k)</span><span class="tag tag-blue">4% match</span></div>
                <div class="pay-row"><span>FSA Balance</span><span style="color:var(--accent2)">$842.50</span></div>
              </div>
              <div class="card" style="margin-top:0">
                <div class="card-title">Tax Forms</div>
                <div class="pay-row"><span>W-2 2025</span><span style="cursor:pointer;color:var(--accent)" onclick="payDlW2(2025)">Download</span></div>
                <div class="pay-row"><span>W-2 2024</span><span style="cursor:pointer;color:var(--accent)" onclick="payDlW2(2024)">Download</span></div>
              </div>
            </div>
          </div>

          <!-- Hourly calculator -->
          <div class="card" style="margin-bottom:16px">
            <div class="card-title">Hourly rate calculator</div>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px">
              <div><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Annual salary</label><input class="ai-input" type="number" id="pay-sal" value="62400" oninput="payCalcHr()" style="width:100%"></div>
              <div><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Hours per week</label><input class="ai-input" type="number" id="pay-hrs" value="40" oninput="payCalcHr()" style="width:100%"></div>
              <div><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Weeks per year</label><input class="ai-input" type="number" id="pay-wks" value="52" oninput="payCalcHr()" style="width:100%"></div>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:20px;background:rgba(56,139,253,.07);border:1px solid rgba(56,139,253,.2);border-radius:6px;padding:14px 18px;margin-bottom:14px">
              <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Hourly rate</div><div id="pay-r-hr" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$30.00</div></div>
              <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Daily (8h)</div><div id="pay-r-day" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$240.00</div></div>
              <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Weekly</div><div id="pay-r-wk" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$1,200.00</div></div>
              <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Bi-weekly</div><div id="pay-r-biwk" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$2,400.00</div></div>
              <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px">Monthly</div><div id="pay-r-mo" style="font-size:18px;font-weight:700;font-family:monospace;color:var(--accent)">$5,200.00</div></div>
            </div>
            <canvas id="pay-hr-bar" height="160"></canvas>
          </div>

          <!-- Tax doc vault -->
          <div class="card" style="margin-bottom:16px">
            <div class="card-title">Tax document vault</div>
            <div id="pay-docs-grid" style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px">
              <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative;transition:border-color .12s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128203;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">W-2 Form &mdash; 2025</div><div style="font-size:11px;color:var(--muted)">Added Jan 31, 2026</div></div>
              <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative;transition:border-color .12s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128203;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">W-2 Form &mdash; 2024</div><div style="font-size:11px;color:var(--muted)">Added Feb 3, 2025</div></div>
              <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative;transition:border-color .12s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(210,153,34,.15);color:#d29922">Pending</span><div style="font-size:20px;margin-bottom:6px">&#128196;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">1099-NEC &mdash; 2025</div><div style="font-size:11px;color:var(--muted)">Awaiting from payer</div></div>
              <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative;transition:border-color .12s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128202;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">Tax deductions log</div><div style="font-size:11px;color:var(--muted)">14 entries &middot; FY 2025</div></div>
              <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative;transition:border-color .12s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(139,148,158,.12);color:var(--muted)">Not uploaded</span><div style="font-size:20px;margin-bottom:6px">&#128193;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">1040 Return &mdash; 2025</div><div style="font-size:11px;color:var(--muted)">Click to upload</div></div>
              <div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative;transition:border-color .12s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'"><span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#10084;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">Benefits statement</div><div style="font-size:11px;color:var(--muted)">Enrollment 2025</div></div>
            </div>
            <div onclick="document.getElementById('pay-file-input').click()" style="border:2px dashed var(--border);border-radius:6px;padding:18px;text-align:center;cursor:pointer;transition:border-color .12s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
              <div style="font-size:11px;color:var(--muted)"><span style="color:var(--accent);font-weight:500">Click to upload</span> a tax document &mdash; W-2 &middot; 1099 &middot; 1040 &middot; PDF &middot; max 25MB</div>
            </div>
            <input type="file" id="pay-file-input" style="display:none" accept=".pdf,.png,.jpg,.jpeg" onchange="payAddDoc(event)">
          </div>

          <!-- Actions -->
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px">
            <button class="btn-primary" onclick="payDlPDF()">Download PDF Report</button>
            <button class="btn-secondary" onclick="payOpenEmail()">Email PDF Report</button>
          </div>
        </div>

        <!-- Email modal -->
        <div id="pay-email-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center">
          <div style="background:var(--surface1);border:1px solid var(--border);border-radius:10px;padding:24px;width:440px;max-width:95vw">
            <div style="font-size:16px;font-weight:700;margin-bottom:18px">Email PDF Report</div>
            <div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Recipient email</label><input class="ai-input" type="email" id="pay-m-to" placeholder="employee@company.com" style="width:100%"></div>
            <div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Your name</label><input class="ai-input" type="text" id="pay-m-name" placeholder="Jamie Vavro" style="width:100%"></div>
            <div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Report type</label><select class="ai-input" id="pay-m-report" style="width:100%"><option>Pay &amp; benefits summary</option><option>Hourly breakdown</option><option>Tax deductions report</option><option>Full package</option></select></div>
            <div style="margin-bottom:12px"><label style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px;font-weight:500">Note (optional)</label><textarea class="ai-input" id="pay-m-note" placeholder="Add a note..." style="width:100%;resize:vertical;min-height:70px"></textarea></div>
            <div id="pay-m-status" style="display:none;font-size:12px;padding:8px 12px;border-radius:6px;margin-bottom:10px"></div>
            <div style="display:flex;gap:10px;justify-content:flex-end">
              <button class="btn-secondary" onclick="payCloseEmail()">Cancel</button>
              <button class="btn-primary" onclick="paySendEmail()">Send Report</button>
            </div>
          </div>
        </div>

        <!-- Chart.js + Pay JS -->
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
        <script>
        var _pBC=null,_pDC=null,_pHC=null;
        function _pInit(){
          if(!window.Chart)return;
          if(!_pBC){var c=document.getElementById('pay-bar-chart');if(c){_pBC=new Chart(c.getContext('2d'),{type:'bar',data:{labels:['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],datasets:[{label:'Gross',data:Array(12).fill(5200),backgroundColor:'rgba(63,185,80,.65)',borderRadius:4},{label:'Net',data:Array(12).fill(3965),backgroundColor:'rgba(56,139,253,.65)',borderRadius:4},{label:'Deductions',data:Array(12).fill(1235),backgroundColor:'rgba(248,81,73,.65)',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{labels:{color:'#8b949e',font:{size:11}}}},scales:{x:{ticks:{color:'#8b949e',font:{size:11}},grid:{color:'rgba(255,255,255,.04)'}},y:{ticks:{color:'#8b949e',font:{size:11},callback:function(v){return'$'+v.toLocaleString();}},grid:{color:'rgba(255,255,255,.04)'}}}}});}}
          if(!_pDC){var d=document.getElementById('pay-donut-chart');if(d){_pDC=new Chart(d.getContext('2d'),{type:'doughnut',data:{datasets:[{data:[468,156,378,145,88],backgroundColor:['#388bfd','#bc8cff','#d29922','#3fb950','#f85149'],borderWidth:0,hoverOffset:5}]},options:{responsive:true,maintainAspectRatio:false,cutout:'68%',plugins:{legend:{display:false}}}});}}
          _pHrBar();
        }
        function _pHrBar(){
          var sal=parseFloat((document.getElementById('pay-sal')||{value:62400}).value)||62400,hrs=parseFloat((document.getElementById('pay-hrs')||{value:40}).value)||40,wks=parseFloat((document.getElementById('pay-wks')||{value:52}).value)||52,g=sal/(hrs*wks),vals=[g,g*.09,g*.03,g*.0765,g*.028,g*.017,g*.763].map(function(v){return+v.toFixed(2);});
          if(_pHC)_pHC.destroy();var hc=document.getElementById('pay-hr-bar');if(!hc||!window.Chart)return;
          _pHC=new Chart(hc.getContext('2d'),{type:'bar',data:{labels:['Gross/hr','Federal','State','FICA','Health','401(k)','Net/hr'],datasets:[{data:vals,backgroundColor:['#3fb950','#388bfd','#bc8cff','#d29922','#f85149','#e3b341','#3fb950'],borderRadius:4}]},options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8b949e',font:{size:11}},grid:{color:'rgba(255,255,255,.04)'}},y:{ticks:{color:'#8b949e',font:{size:11},callback:function(v){return'$'+v.toFixed(2);}},grid:{color:'rgba(255,255,255,.04)'}}}}});
        }
        var _pf=function(n){return'$'+n.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});};
        function payCalcHr(){var sal=parseFloat(document.getElementById('pay-sal').value)||0,hrs=parseFloat(document.getElementById('pay-hrs').value)||40,wks=parseFloat(document.getElementById('pay-wks').value)||52,hr=sal/(hrs*wks);document.getElementById('pay-r-hr').textContent=_pf(hr);document.getElementById('pay-r-day').textContent=_pf(hr*8);document.getElementById('pay-r-wk').textContent=_pf(hr*hrs);document.getElementById('pay-r-biwk').textContent=_pf(hr*hrs*2);document.getElementById('pay-r-mo').textContent=_pf(sal/12);_pHrBar();}
        function payOpenEmail(){var m=document.getElementById('pay-email-modal');if(m)m.style.display='flex';}
        function payCloseEmail(){var m=document.getElementById('pay-email-modal');if(m)m.style.display='none';}
        async function paySendEmail(){var to=document.getElementById('pay-m-to').value.trim(),name=document.getElementById('pay-m-name').value.trim(),report=document.getElementById('pay-m-report').value,note=document.getElementById('pay-m-note').value.trim(),st=document.getElementById('pay-m-status');if(!to||!name){st.textContent='Please fill in recipient email and your name.';st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(248,81,73,.1);color:var(--danger);border:1px solid rgba(248,81,73,.2)';return;}st.textContent='Sending via AI-Prowler...';st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(56,139,253,.08);color:var(--accent);border:1px solid rgba(56,139,253,.2)';try{var res=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:'claude-sonnet-4-6',max_tokens:1000,mcp_servers:[{type:'url',url:'https://ap-david-vavro1-00303282.ai-prowler.com/mcp',name:'ai-prowler'}],messages:[{role:'user',content:'Use send_email tool. To: '+to+' | Name: '+name+' | Report: '+report+' | Note: '+(note||'none')+'. Subject: Your '+report+' - AI-Prowler HR. Body: pay summary Gross $62,400 Net $47,580 Tax 23.7%.'}]})});var data=await res.json(),txt=(data.content||[]).map(function(b){return b.text||(b.content&&b.content[0]&&b.content[0].text)||'';}).join(' ').toLowerCase();st.textContent=(txt.includes('sent')||txt.includes('success'))?'Report sent to '+to:'Delivered to AI-Prowler for '+to;st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(63,185,80,.1);color:var(--accent2);border:1px solid rgba(63,185,80,.2)';}catch(e){st.textContent='Could not reach AI-Prowler email.';st.style.cssText='display:block;font-size:12px;padding:8px 12px;border-radius:6px;background:rgba(248,81,73,.1);color:var(--danger);border:1px solid rgba(248,81,73,.2)';}};
        function payDlPDF(){var b=new Blob(['PAY & BENEFITS - AI-Prowler HR\\nDate: '+new Date().toLocaleDateString()+'\\n\\nPay Stub Aug 31 2026\\nRegular: $2,400 | OT: $180 | Federal: -$312 | State: -$68 | Health: -$124 | 401k: -$96 | Net: $1,980\\n\\nAnnual: Gross $62,400 | Net $47,580 | Tax 23.7% | Hourly $30.00\\nBenefits: Blue Cross PPO | Dental | Vision | 401k 4% | FSA $842.50'],{type:'text/plain'});var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='PayBenefits_'+new Date().toISOString().split('T')[0]+'.txt';a.click();}
        function payDlW2(yr){var b=new Blob(['W-2 '+yr+'\\nEmployee: Jamie Vavro | Employer: AI-Prowler\\nWages: $62,400 | Federal: $5,616 | SS: $3,869 | Medicare: $905'],{type:'text/plain'});var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='W2_'+yr+'.txt';a.click();}
        function payAddDoc(e){var file=e.target.files[0];if(!file)return;var grid=document.getElementById('pay-docs-grid'),d=document.createElement('div');d.style.cssText='background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;cursor:pointer;position:relative';d.innerHTML='<span style="position:absolute;top:10px;right:10px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;background:rgba(63,185,80,.15);color:var(--accent2)">Saved</span><div style="font-size:20px;margin-bottom:6px">&#128196;</div><div style="font-weight:600;font-size:12px;margin-bottom:2px">'+file.name+'</div><div style="font-size:11px;color:var(--muted)">Uploaded today</div>';grid.appendChild(d);}
        document.addEventListener('click',function(e){if(e.target&&e.target.id==='pay-email-modal')payCloseEmail();});
        (function(){var _n=window.navigate;window.navigate=function(el,pg,t){if(typeof _n==='function')_n(el,pg,t);if(pg==='pay')setTimeout(_pInit,200);};if(document.getElementById('page-pay')&&document.getElementById('page-pay').classList.contains('active'))setTimeout(_pInit,400);})();
        </script>

        <!-- TASKS PAGE -->"""

if OLD in html:
    html = html.replace(OLD, NEW, 1)
    with open(dest, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"SUCCESS: Pay & Benefits page updated. File size: {len(html)} bytes")
else:
    print("ERROR: Old pattern not found in file")
    # Print a snippet around 'PAY & BENEFITS' to debug
    idx = html.find('PAY & BENEFITS PAGE')
    if idx >= 0:
        print("Found at index:", idx)
        print(repr(html[idx:idx+500]))
    else:
        print("Page comment not found at all")
