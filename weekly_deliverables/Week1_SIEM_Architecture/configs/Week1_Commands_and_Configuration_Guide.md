# دليل الأوامر والإعدادات الكامل: الأسبوع الأول

**المشروع:** SIEM Detection Engineering, Alert Triage & SOC Operations
**التاريخ:** 7 نوفمبر 2026
**البيئة:** Wazuh 4.14.10 على VirtualBox 7.2.4، وجهاز Ubuntu Server 26.04.1 LTS

**رموز الحالة:**
- ✅ اتنفذ فعلًا في اللاب (موجود في الصور أو في كلامنا)
- 🔎 اتنفذ حسب الخطة لكن مفيش صورة تثبته (راجعه)
- 📄 أمر مرجعي للمساعدة، **ماتنفذش**

**أي VM بينفذ الأمر؟** كل أمر مكتوب فوقه (على Wazuh) أو (على Ubuntu) أو (على الجهاز المضيف).

---

## الفهرس

1. تجهيز الجهاز المضيف
2. تثبيت VirtualBox وتحميل الملفات
3. استيراد Wazuh وضبط الـ VM
4. ضبط الشبكة
5. أول تشغيل لـ Wazuh وفحص الخدمات
6. فتح الـ Dashboard
7. إنشاء VM الـ Ubuntu وتثبيته
8. تثبيت Wazuh Agent
9. توليد الأحداث ومشاهدتها
10. دراسة تركيبة الـ Log وربطها بالحقول
11. تغيير الباسوردات (Hardening)
12. الـ Snapshots
13. الملفات اللي اتعملت في المشروع
14. المشاكل اللي ظهرت وحلولها
15. أوامر مساعدة مرجعية
16. ملخص سريع بكل الأوامر

---

## 1. تجهيز الجهاز المضيف ✅

### الإجراء (بدون أوامر)

1. فتح Task Manager بـ `Ctrl + Shift + Esc`
2. تبويب **Performance** ثم **CPU**
3. قراءة: المعالج، عدد الـ Cores، الـ RAM، نوع الهارد، وحالة **Virtualization**

### النتيجة

| البند | القيمة |
|---|---|
| المعالج | Intel Core i7-6820HQ |
| Cores / Logical | 4 / 8 |
| RAM | 15.9 GB |
| الهارد | SSD، المساحة الفاضية حوالي 350 GB |
| Virtualization | Enabled |

### الشرح

الـ Virtualization لازم تكون Enabled عشان VirtualBox يشغّل أجهزة افتراضية بكفاءة. الـ RAM هي أضعف نقطة (15.9 GB)، فاتحددت الموارد بحذر في الخطوات الجاية.

### الإجراء الاحتياطي لتجهيز المجلدات

```
SOC-Project/
├── Week1_SIEM_Architecture/
│   ├── screenshots/
│   ├── configs/
│   └── notes.md
├── Week2_Detection_Rules/
├── Week3_Dashboards_Triage/
├── Week4_ThreatIntel_SOAR_AI/
└── Final_Report/
```

---

## 2. تثبيت VirtualBox وتحميل الملفات ✅

### على الجهاز المضيف (ويندوز)

| الملف | الحجم التقريبي | الاستخدام |
|---|---|---|
| `VirtualBox-7.2.4-170995-Win.exe` | 172 MB | برنامج تشغيل الأجهزة الافتراضية |
| `wazuh-4.14.10.ova` | 4.9 GB | جهاز Wazuh جاهز (Manager + Indexer + Dashboard) |
| `ubuntu-26.04.1-live-server-amd64.iso` | 2.9 GB | تثبيت جهاز الضحية |

### الشرح

الـ **OVA** هو جهاز افتراضي مجهز مسبقًا، فمش محتاجين نثبت Wazuh من الصفر. الـ **ISO** هو أسطوانة تثبيت نظام التشغيل.

---

## 3. استيراد Wazuh وضبط الـ VM ✅

### المسار في VirtualBox

**File → Import Appliance** ثم اختيار `wazuh-4.14.10.ova`

### الإعدادات النهائية المعتمدة

| الإعداد | القيمة | ملاحظة |
|---|---|---|
| Base Folder | على درايف D: | عشان C: ميتملاش |
| **Base Memory** | **4096 MB** | الافتراضي كان 8192 MB، وكان كبير على جهاز 16 GB |
| Processors | 2 | |
| Disk | `wazuh-4.14.10-disk-1.vdi` (50 GB) | |
| Graphics Controller | VBoxVGA | تحذير VMSVGA في VirtualBox تجاهلناه (معلومة فقط) |

### الشرح

لو الـ VM خدت 8 GB من 16 GB، ويندوز كان هيفضله 8 GB وبعدين نضيف VMs تانية، والجهاز كان هيبطأ أو يهنج. 4 GB كافية لـ Wazuh في لاب فيه Agent واحد.

---

## 4. ضبط الشبكة ✅

### التصميم

| Adapter | النوع | الغرض |
|---|---|---|
| Adapter 1 | **Host-only** | شبكة معزولة للـ VMs وللمتصفح (الـ IP بتاع Wazuh ثابت) |
| Adapter 2 | **NAT** | إنترنت للتحديثات والتحميل |

### الخطوات

**أ) إنشاء شبكة Host-only (مرة واحدة)**

1. في VirtualBox: **File → Tools → Network Manager** (أو `Ctrl + H`)
2. تبويب **Host-only Networks** ثم **Create** (لو مفيش شبكة)
3. الإعدادات:

| الإعداد | القيمة |
|---|---|
| IPv4 Address | `192.168.56.1` |
| IPv4 Network Mask | `255.255.255.0` |
| DHCP Server | Enabled |

**ب) ضبط كروت VM الـ Wazuh**

1. كليك يمين على الـ VM → **Settings → Network**
2. **Adapter 1:** ✅ Enable، Attached to = `Host-only Adapter`، Name = `VirtualBox Host-Only Ethernet Adapter`
3. **Adapter 2:** ✅ Enable (لازم تفعّله بنفسك)، Attached to = `NAT`

### الشرح

الـ Host-only معزولة عن شبكتك الحقيقية، فأي هجوم تجريبي في الأسابيع الجاية مش هيخرج برا. الـ NAT بتدي الـ VM إنترنت بس بدون ما تظهر على الشبكة. وكل VM بتتعامل مع NAT الخاص بيها، عشان كده Wazuh و Ubuntu الاتنين ظاهر عليهم `10.0.3.15` ومفيش تعارض.

### ⚠️ الغلطة اللي حصلت وإزاي اتصلحت

اتغيّر Adapter 1 مرتين (Host-only ثم NAT) بدل ما يتظبط Adapter 2، فبقت الـ VM على NAT بس. الحل: Adapter 1 = Host-only، Adapter 2 = NAT مفعّل، وبعدين تأكدنا بالأوامر اللي في القسم 5.

---

## 5. أول تشغيل لـ Wazuh وفحص الخدمات ✅

### التشغيل

في VirtualBox: اختار الـ VM ثم **Start**، واستنى شاشة تسجيل الدخول (نص أسود).

بيانات الدخول الافتراضية للـ OVA (اتغيّر الباسورد بعدين في القسم 11):

| الحقل | القيمة |
|---|---|
| Username | `wazuh-user` |
| Password | `wazuh` (الافتراضي) |

### الأمر 1: معرفة الـ IP (على Wazuh)

```bash
ip a
```

**الشرح:** `ip a` بيعرض كل كروت الشبكة وعناوينها. بندور على كلمة `inet`.

**النتيجة المتوقعة (اللي ظهرت):**

| الكارت | العنوان | الشبكة |
|---|---|---|
| `eth0` | `10.0.3.15/24` | NAT |
| `eth1` | `192.168.56.110/24` | Host-only (**ده IP الـ Wazuh الرسمي**) |

### الأمر 2: اختبار الإنترنت (على Wazuh)

```bash
ping -c 3 8.8.8.8
```

**الشرح:** بيبعت 3 حزم لسيرفر جوجل DNS. `-c 3` معناها "ابعت 3 مرات وقف". النتيجة المطلوبة: `0% packet loss`، ودي اللي حصلت.

### الأمر 3: فحص الخدمات التلاتة (على Wazuh)

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

**الشرح:**
- `sudo` تنفّذ بصلاحيات المدير
- `systemctl status` يعرض حالة الخدمة
- للخروج من العرض اضغط `q`
- المطلوب: `active (running)` بالأخضر لكل خدمة

| الخدمة | وظيفتها |
|---|---|
| `wazuh-manager` | العقل: يستقبل الـ Logs، يفكها (Decoders)، ويطابقها بالقواعد (Rules) |
| `wazuh-indexer` | قاعدة البيانات: بتخزن الأحداث وتخليها قابلة للبحث |
| `wazuh-dashboard` | الواجهة اللي بتشوف منها التنبيهات |

**النتيجة:** الثلاثة `active (running)` ✅

---

## 6. فتح الـ Dashboard ✅

### من المتصفح

```
https://192.168.56.110
```

1. تظهر رسالة "Your connection is not private" (طبيعي لأن الشهادة self-signed)
2. **Advanced → Proceed**
3. تسجيل الدخول بالمستخدم `admin` وباسوره الافتراضي (اتغيّر في القسم 11)

**النتيجة:** صفحة Overview ظهرت مع "no agents registered"، وده طبيعي قبل تثبيت أي Agent.

---

## 7. إنشاء VM الـ Ubuntu وتثبيته ✅

### إنشاء الـ VM (VirtualBox → New)

| الإعداد | القيمة |
|---|---|
| Name | `Ubuntu-Victim` |
| Folder | على D: |
| ISO | `ubuntu-26.04.1-live-server-amd64.iso` |
| Type / Version | Linux / Ubuntu (64-bit) |
| Skip Unattended Installation | ✅ (تثبيت يدوي) |
| RAM | 2048 MB |
| Disk | 25 GB |

### ضبط الشبكة قبل التشغيل

| Adapter | Attached to |
|---|---|
| Adapter 1 | Host-only Adapter |
| Adapter 2 | NAT |

### خطوات تثبيت Ubuntu Server

| الشاشة | الاختيار |
|---|---|
| Language | English |
| Keyboard | English (US) |
| Type of install | Ubuntu Server |
| Network | Automatic (DHCP) |
| Proxy / Mirror | افتراضي |
| Storage | Use an entire disk |
| Server name | `ubuntu-victim` |
| Username | `victim` |
| SSH | ✅ Install OpenSSH server |
| Featured snaps | بدون اختيار |

بعد التثبيت: **Reboot Now**، ولو ظهرت رسالة `remove the installation medium` اضغط Enter.

### الأوامر بعد أول تشغيل (على Ubuntu)

```bash
ip a
ping 192.168.56.110
```

**الشرح:** `ip a` يعرض العناوين، و`ping` بدون `-c` بيفضل شغال لحد `Ctrl + C`.

**النتيجة:**

| الكارت | العنوان |
|---|---|
| `enp0s3` | `192.168.56.111/24` (Host-only) |
| `enp0s8` | `10.0.3.15/24` (NAT) |
| ping لـ Wazuh | 9 حزم، 0% loss ✅ |

### لماذا SSH؟

بنحتاجه في الأسبوع التاني عشان نهاجم الجهاز ده من Kali (هجوم Brute Force على SSH).

---

## 8. تثبيت Wazuh Agent ✅

### من الـ Dashboard (Deploy new agent)

| الإعداد | القيمة |
|---|---|
| Operating system | Linux, **DEB amd64** |
| Server address | `192.168.56.110` (كتبناه بإيدينا) |
| Agent name | `ubuntu-victim` |
| Group | `default` |

**ليه كتبنا العنوان بإيدينا؟** لأن Wazuh عنده كارتين. لو سيبنا الاختيار التلقائي ممكن ياخد `10.0.3.15` (NAT) والـ Agent مش هيقدر يوصل بيه.

### أمر التثبيت (على Ubuntu)

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.10-1_amd64.deb \
&& sudo WAZUH_MANAGER='192.168.56.110' WAZUH_AGENT_NAME='ubuntu-victim' \
dpkg -i ./wazuh-agent_4.14.10-1_amd64.deb
```

**الشرح جزء بجزء:**

| الجزء | معناه |
|---|---|
| `wget <رابط>` | تنزيل ملف الـ Agent (حجمه حوالي 13 MB) من خلال كارت NAT |
| `&&` | نفّذ الأمر الجاي بس لو الأول نجح |
| `WAZUH_MANAGER='192.168.56.110'` | متغير بيقول للـ Agent يتصل بأنهي سيرفر |
| `WAZUH_AGENT_NAME='ubuntu-victim'` | اسم الجهاز في الـ Dashboard |
| `dpkg -i` | تثبيت حزمة `.deb` محلية |

(بيطلب باسورد sudo وقت التنفيذ.)

### تشغيل الخدمة (على Ubuntu)

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
sudo systemctl daemon-reload
```

**الشرح:**

| الأمر | وظيفته |
|---|---|
| `enable` | تشغيل الـ Agent تلقائيًا كل ما الجهاز يفتح |
| `start` | تشغيله الآن |
| `status` | التأكد إنه `active (running)` |
| `daemon-reload` | إعادة قراءة ملفات الخدمات (ترتيبه مش مهم هنا لأن الـ Agent اشتغل فعلًا) |

### التأكد من الـ Dashboard

**Endpoints → Agents**

| الحقل | القيمة |
|---|---|
| ID | 001 |
| Name | ubuntu-victim |
| IP | 192.168.56.111 |
| OS | Ubuntu 26.04.1 LTS |
| Version | v4.14.10 |
| Status | **active** ✅ |

---

## 9. توليد الأحداث ومشاهدتها ✅

### الأوامر (على Ubuntu)

```bash
# 1) باسورد sudo غلط عمدًا
sudo -k
sudo ls

# 2) إنشاء مستخدم
sudo adduser testuser1

# 3) تسجيل دخول SSH فاشل بمستخدم غير موجود
ssh fakeuser@localhost

# 4) إنشاء ملف في مجلد حساس
sudo touch /etc/test_fim_file
```

**الشرح:**

| الأمر | الهدف | القاعدة اللي ظهرت |
|---|---|---|
| `sudo -k` | مسح الـ cache بتاع الباسورد، فـ `sudo ls` بعده يطلب الباسورد من جديد | |
| `sudo ls` (باسورد غلط مرتين) | محاكاة فشل مصادقة متكرر | `2502` (level 10) |
| `sudo ls` (باسورد صح) | sudo ناجح | `5402` (level 3) |
| `sudo adduser testuser1` | إنشاء مستخدم وجروب | `5902` و`5901` (level 8)، `5555` |
| `ssh fakeuser@localhost` | محاولة دخول بمستخدم غير موجود | `5710` (level 5) |
| `sudo touch /etc/test_fim_file` | تعديل ملف حساس (لاختبار FIM) | `5402` (الأمر نفسه اتسجل كـ sudo) |

### مشاهدة الأحداث

**Threat Hunting → اختار `ubuntu-victim` → تبويب Events → Refresh**

**النتيجة:** 68 hit في أول اختبار.

### ملاحظات

- ملف `test_fim_file` ما ظهرش كحدث File Integrity، لأن الـ FIM في Wazuh بيعمل scan دوري افتراضيًا، والمراقبة اللحظية بتتفعل على مسارات محددة. هنظبطها في الأسبوع التاني.
- كل الـ Source IPs كانت `127.0.0.1` لأن الاختبار اتعمل من نفس الجهاز. في الأسبوع التاني هنهاجم من Kali.

---

## 10. دراسة تركيبة الـ Log وربطها بالحقول ✅

### الإجراء في الـ Dashboard

1. افتح حدث ← أيقونة التوسيع ← تبويب **JSON**
2. انسخ `full_log` وسجّل الحقول

### الـ Logs الخام اللي اتدرست

```
# القاعدة 5710 (SSH)
Nov 07 05:18:10 ubuntu-victim sshd-session[4129]: Invalid user fakeuser from 127.0.0.1 port 59792
Nov 07 05:18:20 ubuntu-victim sshd-session[4129]: Failed password for invalid user fakeuser from 127.0.0.1 port 59792 ssh2

# القاعدة 5402 (sudo)
Nov 07 05:18:43 ubuntu-victim sudo[4141]: victim : TTY=/dev/pts/0 ; PWD=/home/victim ; USER=root ; COMMAND=/usr/bin/touch /etc/test_fim_file

# القاعدة 2502 (PAM)
Nov 07 05:18:33 ubuntu-victim sshd-session[4129]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1
```

### رحلة الـ Log

```
Log خام (journald على Ubuntu)
   → Wazuh Agent (logcollector)
   → Wazuh Manager: Predecoder (وقت، جهاز، برنامج)
   → Decoder (مستخدم، IP، ...)
   → Rules (rule.id, level, MITRE)
   → Indexer → Dashboard
```

### أهم الحقول

| الحقل | معناه |
|---|---|
| `timestamp` | وقت الحدث (UTC) |
| `agent.name` / `agent.id` | الجهاز |
| `data.srcip` | IP المصدر |
| `decoder.name` | الـ Decoder المستخدم |
| `rule.id` / `rule.level` / `rule.description` | القاعدة وخطورتها (0 إلى 15) |
| `rule.mitre.id` / `tactic` | تصنيف MITRE ATT&CK |
| `full_log` | الـ Log الأصلي |
| `location` | مصدر الـ Log على الجهاز (`journald`) |

### ملاحظة الوقت

الـ Dashboard بيعرض بتوقيتك المحلي (UTC+2) فبيظهر `07:18`، لكن الـ Log المخزن بـ UTC فبيظهر `05:18`. كل قواعد الـ Correlation لازم تفترض UTC.

---

## 11. تغيير الباسوردات (Hardening)

### أ) باسورد نظام Wazuh ✅

```bash
passwd
```

**الشرح:** بيطلب الباسورد الحالي، وبعدين الجديد مرتين. النظام رفض أول باسوردين (قصير، وبسيط بالنسبة للـ dictionary check)، وقبل الثالث: `all authentication tokens updated successfully`.

### ب) باسورد `admin` في الـ Dashboard ✅

**Indexer management → Security → Internal users → admin → Edit**، وكتابة باسورد جديد (متطلبات: 8 حروف على الأقل، حرف كبير وصغير، رقم، ورمز). الصفحة أظهرت Password strength = Strong.

### ج) تحديث باسورد Filebeat 🔎

الـ Filebeat هو اللي بيبعت التنبيهات من الـ Manager للـ Indexer، وبيخزن باسورد `admin` عنده. لو اتغير الباسورد في الـ Dashboard من غير ما يتحدّث هنا، التنبيهات ممكن تقف بدون خطأ واضح.

**على Wazuh:**

```bash
sudo filebeat keystore add password --force
sudo systemctl restart filebeat
sudo filebeat test output
```

**الشرح:**

| الأمر | وظيفته |
|---|---|
| `filebeat keystore add password --force` | يخزن الباسورد الجديد (بيطلب إدخاله ولا يظهر في history) |
| `systemctl restart filebeat` | إعادة تشغيل الخدمة بالباسورد الجديد |
| `filebeat test output` | اختبار الاتصال، المطلوب `talk to server... OK` |

**الحالة:** لازم تتأكد منها. لو ظهر `401` أو `unauthorized` فالباسورد غلط.

**اختبار نهائي:** ولّد حدث جديد على Ubuntu (`ssh x@localhost` بباسورد غلط)، وتأكد إن حدث بوقت جديد ظهر في Events.

### ملاحظة أمان

الباسوردات بتتسجل في ملف خاص بيك بره المشروع، وليس في `notes.md` ولا في أي Screenshot.

---

## 12. الـ Snapshots ✅

### من الواجهة

1. (اختياري) اقفل الـ VM بشكل سليم من جواها: `sudo poweroff`
2. اختار الـ VM في VirtualBox ← **Snapshots** ← **Take**
3. الاسم: `Week1_Clean_Baseline`
4. الوصف: `Wazuh configured, agent connected, passwords changed`

اتعملت على VM الـ Wazuh وVM الـ Ubuntu-Victim.

**الشرح:** الـ Snapshot نقطة رجوع. لو بوظت حاجة في هجمات الأسبوع التاني، ترجع لحالة سليمة في ثواني.

### بالأوامر (بديل مرجعي) 📄

على الجهاز المضيف (من Command Prompt داخل مجلد VirtualBox):

```bat
VBoxManage snapshot "Ubuntu-Victim" take "Week1_Clean_Baseline" --description "Wazuh configured, agent connected, passwords changed"
VBoxManage snapshot "Ubuntu-Victim" list
```

---

## 13. الملفات اللي اتعملت في المشروع ✅

| الملف | محتواه |
|---|---|
| `notes.md` | سجل التوثيق لكل خطوة |
| `field_mapping.md` | ربط الـ Logs الخام بالحقول الموحدة (قواعد 5710 و5402 و2502) |
| `data_source_inventory.md` | جرد 13 مصدر بيانات |
| `retention_plan.md` | خطة الاحتفاظ بالـ Logs |
| `siem_architecture_medium_org.svg` | رسمة معمارية الـ SIEM |
| `lab_configuration.md` | إعدادات اللاب |
| `Week1_SIEM_Report.docx` | تقرير الأسبوع الأول بالصور |

**نصيحة VS Code:** `Ctrl + Shift + V` لفتح Markdown Preview بدل النص الخام، فالجداول تظهر مرتبة في الـ Screenshots.

### قاعدة تسمية الصور

`رقم_وصف.png` بالإنجليزي وبدون مسافات، والرقم بيعكس ترتيب التنفيذ (من `01` إلى `33`).

---

## 14. المشاكل اللي ظهرت وحلولها

| المشكلة | السبب | الحل |
|---|---|---|
| RAM الافتراضي 8192 MB كبير | OVA جاي بإعداد أعلى من اللازم | تخفيضه إلى 4096 MB |
| تحذير "Invalid settings detected" | VirtualBox بيوصي بـ VMSVGA كارت شاشة | معلومة فقط، تجاهلناه |
| Wazuh ظهر على NAT بس | Adapter 1 اتغير لـ NAT بدل ضبط Adapter 2 | Adapter 1 = Host-only، Adapter 2 = NAT |
| Ubuntu اتعمل بـ NAT بس | الـ VM اتعملت قبل ضبط الشبكة | إضافة Host-only قبل التثبيت |
| حدث FIM ما ظهرش | الـ FIM بيعمل scan دوري | تفعيل realtime في الأسبوع التاني |
| كل الـ IPs بقت `127.0.0.1` | الاختبار من نفس الجهاز | الهجوم من Kali في الأسبوع التاني |

---

## 15. أوامر مساعدة مرجعية 📄

مش اتنفذت، بس مفيدة لو حصلت مشكلة.

### على Wazuh

```bash
# قائمة الـ Agents ومدى اتصالهم
sudo /var/ossec/bin/agent_control -l

# متابعة لوج الـ Manager لحظيًا (Ctrl+C للخروج)
sudo tail -f /var/ossec/logs/ossec.log

# إعادة تشغيل الـ Manager
sudo systemctl restart wazuh-manager

# مساحة الهارد والذاكرة
df -h
free -h
```

### على Ubuntu

```bash
# حالة الـ Agent
sudo systemctl status wazuh-agent

# لوج الـ Agent (بيبين لو في مشكلة اتصال)
sudo tail -f /var/ossec/logs/ossec.log

# إعادة تشغيل الـ Agent
sudo systemctl restart wazuh-agent

# اختبار الاتصال بالـ Manager (بورت الـ Agents الافتراضي 1514)
nc -zv 192.168.56.110 1514
```

### لو الـ Dashboard مش بيفتح

1. استنى 3 إلى 5 دقايق بعد تشغيل الـ VM
2. على Wazuh: `sudo systemctl status wazuh-dashboard`
3. تأكد إن العنوان `https://192.168.56.110` (وليس `http`)

---

## 16. ملخص سريع بكل الأوامر ✅

### على Wazuh

```bash
ip a
ping -c 3 8.8.8.8
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
passwd
sudo filebeat keystore add password --force     # 🔎
sudo systemctl restart filebeat                 # 🔎
sudo filebeat test output                       # 🔎
sudo poweroff
```

### على Ubuntu

```bash
ip a
ping 192.168.56.110

wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.10-1_amd64.deb \
&& sudo WAZUH_MANAGER='192.168.56.110' WAZUH_AGENT_NAME='ubuntu-victim' \
dpkg -i ./wazuh-agent_4.14.10-1_amd64.deb

sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
sudo systemctl daemon-reload

sudo -k
sudo ls
sudo adduser testuser1
ssh fakeuser@localhost
sudo touch /etc/test_fim_file
sudo poweroff
```

### من الواجهات

| الأداة | الإجراء |
|---|---|
| VirtualBox | Import Appliance، New VM، Network Manager، Settings → Network، Snapshots |
| Dashboard | Deploy new agent، Threat Hunting → Events، Security → Internal users |
| VS Code | `Ctrl + Shift + V` لـ Markdown Preview |

---

## الخلاصة

| الجهاز | الدور | العنوان | الحالة |
|---|---|---|---|
| wazuh-server | SIEM | 192.168.56.110 | ✅ يعمل |
| ubuntu-victim | Endpoint (Agent 001) | 192.168.56.111 | ✅ active |
| Kali_linux | Attacker | لم يُستخدم بعد | يجهز في الأسبوع الثاني |

**ما لم يتغير:** ملفات إعدادات Wazuh الداخلية (`ossec.conf`) كلها افتراضية. كل اللي اتعدّل هو إعدادات VirtualBox والشبكة، وتثبيت الـ Agent، والباسوردات.
