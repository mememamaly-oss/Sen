(globalThis.TURBOPACK || (globalThis.TURBOPACK = [])).push([typeof document === "object" ? document.currentScript : undefined,
"[project]/src/lib/ui/i18n.tsx [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "I18nProvider",
    ()=>I18nProvider,
    "useI18n",
    ()=>useI18n
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/jsx-dev-runtime.js [app-client] (ecmascript)");
// SENTINEL i18n — Arabic-first (default) with English. RTL/LTR follows the
// locale. UI strings only; user-generated content (target names, engine
// finding types, audit actions) is displayed as-is.
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)");
;
var _s = __turbopack_context__.k.signature(), _s1 = __turbopack_context__.k.signature();
"use client";
;
const DICT = {
    ar: {
        "brand.name": "SENTINEL",
        "brand.tagline": "منصة استخبارات الأمن",
        "nav.overview": "نظرة عامة",
        "nav.targets": "الأهداف",
        "nav.scans": "الفحوصات",
        "nav.findings": "الثغرات",
        "nav.reports": "التقارير",
        "nav.twin": "التوأم الرقمي",
        "nav.organization": "المنظمة",
        "nav.audit": "سجل التدقيق",
        "nav.section.main": "العمليات",
        "nav.section.governance": "الحوكمة",
        "common.loading": "جارٍ التحميل…",
        "common.retry": "إعادة المحاولة",
        "common.error": "تعذر تحميل البيانات",
        "common.empty": "لا توجد بيانات بعد",
        "common.search": "بحث",
        "common.filter": "تصفية",
        "common.sort": "ترتيب",
        "common.all": "الكل",
        "common.actions": "إجراءات",
        "common.details": "التفاصيل",
        "common.view": "عرض",
        "common.create": "إنشاء",
        "common.cancel": "إلغاء",
        "common.confirm": "تأكيد",
        "common.close": "إغلاق",
        "common.save": "حفظ",
        "common.delete": "حذف",
        "common.open": "فتح",
        "common.back": "رجوع",
        "common.download": "تنزيل",
        "common.refresh": "تحديث",
        "common.none": "لا شيء",
        "common.yes": "نعم",
        "common.no": "لا",
        "common.more": "المزيد",
        "common.vs": "مقابل",
        "common.of": "من",
        "time.now": "الآن",
        "time.sec": "ث",
        "time.min": "د",
        "time.hour": "س",
        "login.title": "تسجيل الدخول",
        "login.subtitle": "الوصول إلى منصة استخبارات الأمن",
        "login.email": "البريد الإلكتروني",
        "login.password": "كلمة المرور",
        "login.submit": "دخول",
        "login.working": "جارٍ الدخول…",
        "login.invalid": "بيانات الدخول غير صحيحة",
        "login.bootstrapTitle": "تنشيط المنصة",
        "login.bootstrapHint": "لا يوجد أي مستخدم بعد — أنشئ حساب المسؤول الأول (مالك المنظمة الافتراضية).",
        "login.orgName": "اسم المنظمة",
        "login.yourName": "اسمك",
        "login.bootstrapSubmit": "تنشيط",
        "login.secureNote": "جلسات مشفّرة — كلمات المرور مخزنة كـ scrypt ولا تُعرض أبدًا.",
        "theme.toLight": "الوضع الفاتح",
        "theme.toDark": "الوضع الداكن",
        "locale.switch": "English",
        "user.signOut": "تسجيل الخروج",
        "user.signedOut": "تم تسجيل الخروج",
        "shell.skipToContent": "تخطَّ إلى المحتوى",
        "shell.org": "المنظمة",
        "shell.switchOrg": "تبديل المنظمة",
        "shell.nav": "التنقل",
        "shell.navDesc": "التنقل الرئيسي بين أقسام المنصة",
        "palette.title": "لوحة الأوامر",
        "palette.placeholder": "ابحث عن صفحة…",
        "palette.empty": "لا توجد نتائج",
        "palette.open": "فتح لوحة الأوامر",
        "shell.role.owner": "مالك",
        "shell.role.admin": "مدير",
        "shell.role.member": "عضو",
        "shell.role.viewer": "مشاهد",
        "overview.title": "نظرة عامة",
        "overview.subtitle.exec": "لوحة تنفيذية — وضع الأمن الحالي",
        "overview.kpi.targets": "الأهداف",
        "overview.kpi.scans": "الفحوصات",
        "overview.kpi.findings": "الثغرات",
        "overview.kpi.reports": "التقارير",
        "overview.kpi.coverage": "التغطية",
        "overview.severityMix": "توزيع الخطورة",
        "overview.severityMixEmpty": "لا توجد ثغرات مسجلة بعد — شغّل فحصًا أولًا",
        "overview.recentScans": "أحدث الفحوصات",
        "overview.recentEmpty": "لم يُشغَّل أي فحص بعد",
        "overview.viewAll": "عرض الكل",
        "overview.lastScan": "آخر فحص مكتمل",
        "overview.noCompleted": "لا يوجد فحص مكتمل بعد",
        "overview.engine": "المحرك",
        "overview.scanner": "الماسح",
        "overview.duration": "المدة",
        "overview.findingsFound": "ثغرة",
        "targets.title": "الأهداف",
        "targets.subtitle": "أسطح الهجوم المسجلة تحت منظمتك",
        "targets.empty.title": "لا توجد أهداف",
        "targets.empty.hint": "أضف هدفًا لبدء أول فحص — يمكنك استخدام التطبيق التجريبي المُدار",
        "targets.add": "إضافة هدف",
        "targets.addDemo": "إضافة التطبيق التجريبي",
        "targets.addCustom": "هدف مخصص",
        "targets.name": "الاسم",
        "targets.url": "العنوان",
        "targets.description": "الوصف",
        "targets.owner": "المالك",
        "targets.scansCount": "فحوصات",
        "targets.findingsCount": "ثغرات",
        "targets.lastScan": "آخر فحص",
        "targets.never": "لم يُفحص بعد",
        "targets.demoBadge": "مُدار",
        "targets.newScan": "فحص جديد",
        "targets.searchPlaceholder": "ابحث بالاسم أو العنوان…",
        "targets.sort.newest": "الأحدث",
        "targets.sort.mostScans": "الأكثر فحصًا",
        "targets.sort.mostFindings": "الأكثر ثغرات",
        "targets.deleteConfirmTitle": "حذف الهدف؟",
        "targets.deleteConfirmBody": "سيُحذف الهدف وسجلّه. لا يمكن التراجع.",
        "targets.created": "أُضيف الهدف",
        "targets.deleted": "حُذف الهدف",
        "targets.invalidUrl": "العنوان غير صالح — يجب أن يبدأ بـ http:// أو https://",
        "scans.title": "الفحوصات",
        "scans.subtitle": "كل عمليات المسح ونتائجها",
        "scans.empty.title": "لا توجد فحوصات",
        "scans.empty.hint": "ابدأ فحصًا من صفحة الأهداف",
        "scans.status": "الحالة",
        "scans.status.QUEUED": "في الطابور",
        "scans.status.RUNNING": "قيد التشغيل",
        "scans.status.COMPLETED": "مكتمل",
        "scans.status.FAILED": "فشل",
        "scans.status.CANCELLED": "ملغى",
        "scans.target": "الهدف",
        "scans.startedBy": "بواسطة",
        "scans.duration": "المدة",
        "scans.coverage": "التغطية",
        "scans.runId": "معرّف التشغيلة",
        "scans.live": "مباشر",
        "scans.monitor.title": "مراقبة الفحص",
        "scans.monitor.elapsed": "المنقضي",
        "scans.monitor.eta": "المتوقع",
        "scans.monitor.cpu": "زمن المعالج",
        "scans.monitor.connections": "اتصالات نشطة",
        "scans.monitor.engineLog": "سجل المحرك",
        "scans.monitor.cancel": "إلغاء الفحص",
        "scans.monitor.cancelConfirmTitle": "إلغاء الفحص؟",
        "scans.monitor.cancelConfirmBody": "سيُوقف المسح الحالي. النتائج المستوردة حتى الآن تبقى.",
        "scans.monitor.findingsImported": "استوردت النتائج",
        "scans.monitor.noFindingsYet": "النتائج تُستورد عند اكتمال المحرك",
        "scans.started": "انطلق الفحص",
        "scans.cancelled": "أُلغي الفحص",
        "scans.start": "بدء فحص",
        "scans.starting": "جارٍ البدء…",
        "scans.startConfirmTitle": "بدء فحص جديد؟",
        "scans.startConfirmBody": "سيشغّل المحرك (sentinel-core/4.1.1) فحصًا حقيقيًا لهذا الهدف الآن، ويمكنك مراقبته مباشرة.",
        "scans.statusFilter.all": "كل الحالات",
        "scans.failedReason": "السبب",
        "findings.title": "الثغرات",
        "findings.subtitle": "كل ما رصده المحرك — بأدلة قابلة للإعادة",
        "findings.pickScan": "اختر فحصًا",
        "findings.empty.title": "لا توجد ثغرات",
        "findings.empty.hint": "إمّا لم يكتمل الفحص أو لم يرصد شيئًا — الصدق قبل التضخيم",
        "findings.type": "النوع",
        "findings.severity": "الخطورة",
        "findings.verification": "التحقق",
        "findings.confidence": "الثقة",
        "findings.risk": "الخطر",
        "findings.url": "المواضع",
        "findings.sort.newest": "الأحدث",
        "findings.sort.severity": "بالخطورة",
        "findings.sort.confidence": "بالثقة",
        "findings.sort.risk": "بالخطر",
        "findings.verified": "متحقق",
        "findings.unverified": "غير متحقق",
        "findings.searchPlaceholder": "ابحث بالنوع أو المواضع…",
        "finding.detail.evidence": "الدليل",
        "finding.detail.verification": "التحقق",
        "finding.detail.impact": "الأثر",
        "finding.detail.reproduction": "الإعادة",
        "finding.detail.remediation": "المعالجة",
        "finding.detail.fingerprint": "البصمة",
        "finding.detail.engineId": "معرّف المحرك",
        "finding.detail.confidence": "درجة الثقة",
        "finding.detail.risk": "درجة الخطر",
        "finding.detail.proof": "قيد الإثبات",
        "finding.detail.noReproduction": "لا توجد وصفة إعادة من المحرك لهذه النتيجة — يُعرض ما هو متاح فقط",
        "finding.detail.remediationNote": "إرشاد من جانب المنصة (ليس مخرج المحرك المباشر)",
        "severity.critical": "حرجة",
        "severity.high": "مرتفعة",
        "severity.medium": "متوسطة",
        "severity.low": "منخفضة",
        "severity.info": "معلومة",
        "reports.title": "التقارير",
        "reports.subtitle": "مخرجات رسمية من عمليات الفحص",
        "reports.empty.title": "لا توجد تقارير",
        "reports.empty.hint": "أنشئ تقريرًا من فحص مكتمل",
        "reports.create": "إنشاء تقرير",
        "reports.format": "الصيغة",
        "reports.size": "الحجم",
        "reports.createdBy": "بواسطة",
        "reports.scan": "الفحص",
        "reports.generate": "توليد",
        "reports.generated": "وُلّد التقرير",
        "reports.viewer.raw": "المحتوى الخام",
        "reports.viewer.unavailable": "تعذر عرض محتوى التقرير",
        "reports.downloadHint": "الملف الأصلي متاح للتنزيل",
        "twin.title": "التوأم الرقمي",
        "twin.subtitle": "خريطة المعرفة الأمنية للتطبيق — من بيانات المحرك الحالية",
        "twin.phaseNote": "عرض المرحلة الحالية: إحصاءات واقعية من آخر فحص مكتمل. الرسم البياني التفاعلي الكامل قادم في المرحلة 02 من خارطة الطريق.",
        "twin.stats.nodes": "العقد",
        "twin.stats.edges": "الحواف",
        "twin.stats.surfaces": "الأسطح",
        "twin.stats.entities": "الكيانات",
        "twin.stats.rolls": "الأدوار",
        "twin.noData": "لا يوجد فحص مكتمل بعد — التوأم يُبنى من بيانات فحص حقيقية فقط",
        "twin.coverageDimensions": "أبعاد التغطية",
        "twin.l1.title": "التوأم الأمني المُطبَّع",
        "twin.l1.subtitle": "نموذج أمني حتمي مُعاد بناؤه من أدلة الفحص — المرحلة L1",
        "twin.l1.scan": "الفحص",
        "twin.l1.changeScan": "تغيير الفحص",
        "twin.l1.hash": "بصمة التوأم (twinHash)",
        "twin.l1.provenance": "المصدرية",
        "twin.l1.claims": "المطالبات",
        "twin.l1.conflicts": "التعارضات",
        "twin.l1.unknowns": "المجهولات المعروفة",
        "twin.l1.why": "لماذا هذا العنصر موجود؟",
        "twin.l1.why.reason": "السبب",
        "twin.l1.why.sources": "المراجع في مخرجات المحرك",
        "twin.l1.why.inference": "قاعدة الاستنتاج",
        "twin.l1.why.evidence": "الأدلة المرجعية",
        "twin.l1.attrs": "الخصائص",
        "twin.l1.related": "العلاقات المرتبطة",
        "twin.l1.graph": "خريطة الرسم البياني",
        "twin.l1.graph.cap": "يُعرض {{shown}} من {{total}} عقدة (تخطيط حتمي — الأهم أولاً)",
        "twin.l1.nodes": "العقد",
        "twin.l1.edges": "الحواف",
        "twin.l1.claim.VERIFIED": "مُثبتة بأدلة",
        "twin.l1.claim.REFUTED": "مُفَنَّدة",
        "twin.l1.claim.UNKNOWN": "غير محسومة",
        "twin.l1.claim.CONFLICT": "متعارضة",
        "twin.l1.filter.type": "النوع",
        "twin.l1.filter.provenance": "المصدرية",
        "twin.l1.scope": "نطاق الفحص",
        "twin.l1.built": "مُولّد الآن",
        "twin.l1.stored": "من المخزن",
        "twin.l1.noTwin": "لا توجد مخرجات محرك قابلة للتطبيع لهذا الفحص",
        "twin.l1.conflict.desc": "أدلة متعارضة — لا يتم اختيار رواية دون الأخرى",
        "twin.l1.invariants": "الثوابت",
        "twin.l1.invariants.pass": "اجتياز جميع الثوابت",
        "twin.l1.invariants.fail": "خرق ثوابت",
        "org.title": "المنظمة",
        "org.subtitle": "الهوية والأعضاء والأدوار",
        "org.members": "الأعضاء",
        "org.member.add": "إضافة عضو",
        "org.member.email": "البريد الإلكتروني",
        "org.member.name": "الاسم",
        "org.member.role": "الدور",
        "org.member.password": "كلمة مرور مؤقتة (٨ أحرف على الأقل)",
        "org.member.joined": "انضم في",
        "org.member.added": "أُضيف العضو",
        "org.member.roleChanged": "غُيّر الدور",
        "org.member.removed": "أُزيل العضو",
        "org.member.removeConfirmTitle": "إزالة العضو؟",
        "org.member.removeConfirmBody": "يفقد العضو وصوله لهذه المنظمة.",
        "org.member.self": "أنت",
        "org.about": "عن المنظمة",
        "org.slug": "المعرّف",
        "org.createdAt": "أنشئت في",
        "audit.title": "سجل التدقيق",
        "audit.subtitle": "سجل append-only لكل إجراء — لا حذف ولا تعديل",
        "audit.action": "الإجراء",
        "audit.by": "الفاعل",
        "audit.when": "الوقت",
        "audit.detail": "التفاصيل",
        "audit.empty": "لا توجد أحداث بعد",
        "audit.searchPlaceholder": "ابحث في الإجراء أو الفاعل…",
        "toasts.signedIn": "تم تسجيل الدخول",
        "toasts.errorGeneric": "حدث خطأ غير متوقع"
    },
    en: {
        "brand.name": "SENTINEL",
        "brand.tagline": "Security Intelligence Platform",
        "nav.overview": "Overview",
        "nav.targets": "Targets",
        "nav.scans": "Scans",
        "nav.findings": "Findings",
        "nav.reports": "Reports",
        "nav.twin": "Digital Twin",
        "nav.organization": "Organization",
        "nav.audit": "Audit Log",
        "nav.section.main": "Operations",
        "nav.section.governance": "Governance",
        "common.loading": "Loading…",
        "common.retry": "Retry",
        "common.error": "Could not load data",
        "common.empty": "Nothing here yet",
        "common.search": "Search",
        "common.filter": "Filter",
        "common.sort": "Sort",
        "common.all": "All",
        "common.actions": "Actions",
        "common.details": "Details",
        "common.view": "View",
        "common.create": "Create",
        "common.cancel": "Cancel",
        "common.confirm": "Confirm",
        "common.close": "Close",
        "common.save": "Save",
        "common.delete": "Delete",
        "common.open": "Open",
        "common.back": "Back",
        "common.download": "Download",
        "common.refresh": "Refresh",
        "common.none": "None",
        "common.yes": "Yes",
        "common.no": "No",
        "common.more": "More",
        "common.vs": "vs",
        "common.of": "of",
        "time.now": "now",
        "time.sec": "s",
        "time.min": "m",
        "time.hour": "h",
        "login.title": "Sign in",
        "login.subtitle": "Access the security intelligence platform",
        "login.email": "Email",
        "login.password": "Password",
        "login.submit": "Sign in",
        "login.working": "Signing in…",
        "login.invalid": "Invalid credentials",
        "login.bootstrapTitle": "Platform activation",
        "login.bootstrapHint": "No users exist yet — create the first admin (default org owner).",
        "login.orgName": "Organization name",
        "login.yourName": "Your name",
        "login.bootstrapSubmit": "Activate",
        "login.secureNote": "Encrypted sessions — passwords stored as scrypt, never exposed.",
        "theme.toLight": "Light mode",
        "theme.toDark": "Dark mode",
        "locale.switch": "العربية",
        "user.signOut": "Sign out",
        "user.signedOut": "Signed out",
        "shell.skipToContent": "Skip to content",
        "shell.org": "Organization",
        "shell.switchOrg": "Switch organization",
        "shell.nav": "Navigation",
        "shell.navDesc": "Primary navigation between platform sections",
        "palette.title": "Command palette",
        "palette.placeholder": "Search pages…",
        "palette.empty": "No results found",
        "palette.open": "Open command palette",
        "shell.role.owner": "Owner",
        "shell.role.admin": "Admin",
        "shell.role.member": "Member",
        "shell.role.viewer": "Viewer",
        "overview.title": "Overview",
        "overview.subtitle.exec": "Executive dashboard — current security posture",
        "overview.kpi.targets": "Targets",
        "overview.kpi.scans": "Scans",
        "overview.kpi.findings": "Findings",
        "overview.kpi.reports": "Reports",
        "overview.kpi.coverage": "Coverage",
        "overview.severityMix": "Severity mix",
        "overview.severityMixEmpty": "No findings recorded yet — run a first scan",
        "overview.recentScans": "Recent scans",
        "overview.recentEmpty": "No scans have been run yet",
        "overview.viewAll": "View all",
        "overview.lastScan": "Last completed scan",
        "overview.noCompleted": "No completed scan yet",
        "overview.engine": "Engine",
        "overview.scanner": "Scanner",
        "overview.duration": "Duration",
        "overview.findingsFound": "findings",
        "targets.title": "Targets",
        "targets.subtitle": "The attack surfaces registered under your organization",
        "targets.empty.title": "No targets",
        "targets.empty.hint": "Add a target to start scanning — the managed demo app is one click away",
        "targets.add": "Add target",
        "targets.addDemo": "Add demo app",
        "targets.addCustom": "Custom target",
        "targets.name": "Name",
        "targets.url": "URL",
        "targets.description": "Description",
        "targets.owner": "Owner",
        "targets.scansCount": "Scans",
        "targets.findingsCount": "Findings",
        "targets.lastScan": "Last scan",
        "targets.never": "Never scanned",
        "targets.demoBadge": "Managed",
        "targets.newScan": "New scan",
        "targets.searchPlaceholder": "Search by name or URL…",
        "targets.sort.newest": "Newest",
        "targets.sort.mostScans": "Most scanned",
        "targets.sort.mostFindings": "Most findings",
        "targets.deleteConfirmTitle": "Delete target?",
        "targets.deleteConfirmBody": "The target and its history will be deleted. This cannot be undone.",
        "targets.created": "Target added",
        "targets.deleted": "Target deleted",
        "targets.invalidUrl": "Invalid URL — must start with http:// or https://",
        "scans.title": "Scans",
        "scans.subtitle": "Every scan run and its outcome",
        "scans.empty.title": "No scans",
        "scans.empty.hint": "Start one from the Targets page",
        "scans.status": "Status",
        "scans.status.QUEUED": "Queued",
        "scans.status.RUNNING": "Running",
        "scans.status.COMPLETED": "Completed",
        "scans.status.FAILED": "Failed",
        "scans.status.CANCELLED": "Cancelled",
        "scans.target": "Target",
        "scans.startedBy": "By",
        "scans.duration": "Duration",
        "scans.coverage": "Coverage",
        "scans.runId": "Run ID",
        "scans.live": "LIVE",
        "scans.monitor.title": "Scan monitoring",
        "scans.monitor.elapsed": "Elapsed",
        "scans.monitor.eta": "ETA",
        "scans.monitor.cpu": "CPU time",
        "scans.monitor.connections": "Active connections",
        "scans.monitor.engineLog": "Engine log",
        "scans.monitor.cancel": "Cancel scan",
        "scans.monitor.cancelConfirmTitle": "Cancel scan?",
        "scans.monitor.cancelConfirmBody": "The current run stops. Findings imported so far remain.",
        "scans.monitor.findingsImported": "Findings imported",
        "scans.monitor.noFindingsYet": "Findings import when the engine finishes",
        "scans.started": "Scan started",
        "scans.cancelled": "Scan cancelled",
        "scans.start": "Start scan",
        "scans.starting": "Starting…",
        "scans.startConfirmTitle": "Start a new scan?",
        "scans.startConfirmBody": "The engine (sentinel-core/4.1.1) will run a real scan against this target now — you can watch it live.",
        "scans.statusFilter.all": "All statuses",
        "scans.failedReason": "Reason",
        "findings.title": "Findings",
        "findings.subtitle": "Everything the engine observed — with reproducible evidence",
        "findings.pickScan": "Pick a scan",
        "findings.empty.title": "No findings",
        "findings.empty.hint": "Either the scan is not complete or it observed nothing — honesty over inflation",
        "findings.type": "Type",
        "findings.severity": "Severity",
        "findings.verification": "Verification",
        "findings.confidence": "Confidence",
        "findings.risk": "Risk",
        "findings.url": "Locations",
        "findings.sort.newest": "Newest",
        "findings.sort.severity": "By severity",
        "findings.sort.confidence": "By confidence",
        "findings.sort.risk": "By risk",
        "findings.verified": "Verified",
        "findings.unverified": "Unverified",
        "findings.searchPlaceholder": "Search by type or location…",
        "finding.detail.evidence": "Evidence",
        "finding.detail.verification": "Verification",
        "finding.detail.impact": "Impact",
        "finding.detail.reproduction": "Reproduction",
        "finding.detail.remediation": "Remediation",
        "finding.detail.fingerprint": "Fingerprint",
        "finding.detail.engineId": "Engine ID",
        "finding.detail.confidence": "Confidence",
        "finding.detail.risk": "Risk",
        "finding.detail.proof": "In proof",
        "finding.detail.noReproduction": "No reproduction recipe emitted by the engine for this finding — only what exists is shown",
        "finding.detail.remediationNote": "Platform-side guidance (not direct engine output)",
        "severity.critical": "Critical",
        "severity.high": "High",
        "severity.medium": "Medium",
        "severity.low": "Low",
        "severity.info": "Info",
        "reports.title": "Reports",
        "reports.subtitle": "Official outputs from scan runs",
        "reports.empty.title": "No reports",
        "reports.empty.hint": "Create one from a completed scan",
        "reports.create": "Create report",
        "reports.format": "Format",
        "reports.size": "Size",
        "reports.createdBy": "By",
        "reports.scan": "Scan",
        "reports.generate": "Generate",
        "reports.generated": "Report generated",
        "reports.viewer.raw": "Raw content",
        "reports.viewer.unavailable": "Could not render the report content",
        "reports.downloadHint": "The original file is available to download",
        "twin.title": "Digital Twin",
        "twin.subtitle": "The application's security knowledge graph — from current engine data",
        "twin.phaseNote": "Phase 01 view: real statistics from the latest completed scan. The full interactive graph is Phase 02 of the ratified roadmap.",
        "twin.stats.nodes": "Nodes",
        "twin.stats.edges": "Edges",
        "twin.stats.surfaces": "Surfaces",
        "twin.stats.entities": "Entities",
        "twin.stats.rolls": "Rolls",
        "twin.noData": "No completed scan yet — the twin is built from real scan data only",
        "twin.coverageDimensions": "Coverage dimensions",
        "twin.l1.title": "Normalized Security Twin",
        "twin.l1.subtitle": "A deterministic security model rebuilt from scan evidence — Phase L1",
        "twin.l1.scan": "Scan",
        "twin.l1.changeScan": "Change scan",
        "twin.l1.hash": "Twin hash",
        "twin.l1.provenance": "Provenance",
        "twin.l1.claims": "Claims",
        "twin.l1.conflicts": "Conflicts",
        "twin.l1.unknowns": "Known unknowns",
        "twin.l1.why": "Why does this element exist?",
        "twin.l1.why.reason": "Reason",
        "twin.l1.why.sources": "Engine output references",
        "twin.l1.why.inference": "Inference rule",
        "twin.l1.why.evidence": "Evidence references",
        "twin.l1.attrs": "Attributes",
        "twin.l1.related": "Related edges",
        "twin.l1.graph": "Graph map",
        "twin.l1.graph.cap": "Showing {{shown}} of {{total}} nodes (deterministic layout — most important first)",
        "twin.l1.nodes": "Nodes",
        "twin.l1.edges": "Edges",
        "twin.l1.claim.VERIFIED": "Verified with evidence",
        "twin.l1.claim.REFUTED": "Refuted",
        "twin.l1.claim.UNKNOWN": "Undetermined",
        "twin.l1.claim.CONFLICT": "Conflicting",
        "twin.l1.filter.type": "Type",
        "twin.l1.filter.provenance": "Provenance",
        "twin.l1.scope": "Scan scope",
        "twin.l1.built": "Built now",
        "twin.l1.stored": "From store",
        "twin.l1.noTwin": "No normalizable engine output for this scan",
        "twin.l1.conflict.desc": "Conflicting evidence — neither story is picked over the other",
        "twin.l1.invariants": "Invariants",
        "twin.l1.invariants.pass": "All invariants pass",
        "twin.l1.invariants.fail": "Invariant violations",
        "org.title": "Organization",
        "org.subtitle": "Identity, members and roles",
        "org.members": "Members",
        "org.member.add": "Add member",
        "org.member.email": "Email",
        "org.member.name": "Name",
        "org.member.role": "Role",
        "org.member.password": "Temp password (min 8 chars)",
        "org.member.joined": "Joined",
        "org.member.added": "Member added",
        "org.member.roleChanged": "Role changed",
        "org.member.removed": "Member removed",
        "org.member.removeConfirmTitle": "Remove member?",
        "org.member.removeConfirmBody": "The member loses access to this organization.",
        "org.member.self": "You",
        "org.about": "About",
        "org.slug": "Slug",
        "org.createdAt": "Created",
        "audit.title": "Audit Log",
        "audit.subtitle": "Append-only record of every action — no deletes, no edits",
        "audit.action": "Action",
        "audit.by": "Actor",
        "audit.when": "When",
        "audit.detail": "Detail",
        "audit.empty": "No events yet",
        "audit.searchPlaceholder": "Search action or actor…",
        "toasts.signedIn": "Signed in",
        "toasts.errorGeneric": "Unexpected error"
    }
};
const Ctx = /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["createContext"])(null);
function pick() {
    if ("TURBOPACK compile-time falsy", 0) //TURBOPACK unreachable
    ;
    const saved = window.localStorage.getItem("sentinel.locale");
    return saved === "en" || saved === "ar" ? saved : "ar";
}
function I18nProvider({ children }) {
    _s();
    const [locale, setLocaleState] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useState"])("ar");
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "I18nProvider.useEffect": ()=>{
            setLocaleState(pick());
        }
    }["I18nProvider.useEffect"], []);
    const setLocale = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "I18nProvider.useCallback[setLocale]": (l)=>{
            setLocaleState(l);
            try {
                window.localStorage.setItem("sentinel.locale", l);
            } catch  {
            /* private mode */ }
        }
    }["I18nProvider.useCallback[setLocale]"], []);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "I18nProvider.useEffect": ()=>{
            const dir = locale === "ar" ? "rtl" : "ltr";
            document.documentElement.setAttribute("dir", dir);
            document.documentElement.setAttribute("lang", locale);
        }
    }["I18nProvider.useEffect"], [
        locale
    ]);
    const value = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useMemo"])({
        "I18nProvider.useMemo[value]": ()=>{
            const t = {
                "I18nProvider.useMemo[value].t": (key)=>DICT[locale][key] ?? key
            }["I18nProvider.useMemo[value].t"];
            const dateLocale = locale === "ar" ? "ar-LY" : "en-GB";
            return {
                locale,
                dir: locale === "ar" ? "rtl" : "ltr",
                t,
                setLocale,
                fmtDate (iso, opts) {
                    if (!iso) return "—";
                    const d = new Date(iso);
                    if (opts?.time === false) return d.toLocaleDateString(dateLocale, {
                        dateStyle: "medium"
                    });
                    return d.toLocaleString(dateLocale, {
                        dateStyle: "medium",
                        timeStyle: "short",
                        hour12: false
                    });
                },
                fmtNum (n) {
                    if (n === null || n === undefined) return "—";
                    return n.toLocaleString(dateLocale);
                },
                fmtBytes (b) {
                    if (b === null || b === undefined) return "—";
                    if (b < 1024) return `${b} B`;
                    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
                    return `${(b / 1024 / 1024).toFixed(2)} MB`;
                },
                fmtDuration (sec) {
                    if (sec === null || sec === undefined) return "—";
                    const unit = locale === "ar" ? {
                        s: "ث",
                        m: "د",
                        h: "س"
                    } : {
                        s: "s",
                        m: "m",
                        h: "h"
                    };
                    if (sec < 60) return `${Math.round(sec)}${unit.s}`;
                    if (sec < 3600) return `${Math.floor(sec / 60)}${unit.m} ${Math.round(sec % 60)}${unit.s}`;
                    return `${Math.floor(sec / 3600)}${unit.h} ${Math.floor(sec % 3600 / 60)}${unit.m}`;
                },
                relTime (iso) {
                    if (!iso) return "—";
                    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
                    const justNow = locale === "ar" ? "الآن" : "now";
                    if (Math.abs(diff) < 60) return justNow;
                    const rtf = new Intl.RelativeTimeFormat(dateLocale, {
                        numeric: "auto"
                    });
                    if (Math.abs(diff) < 3600) return rtf.format(-Math.round(diff / 60), "minute");
                    if (Math.abs(diff) < 86400) return rtf.format(-Math.round(diff / 3600), "hour");
                    return rtf.format(-Math.round(diff / 86400), "day");
                }
            };
        }
    }["I18nProvider.useMemo[value]"], [
        locale,
        setLocale
    ]);
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(Ctx.Provider, {
        value: value,
        children: children
    }, void 0, false, {
        fileName: "[project]/src/lib/ui/i18n.tsx",
        lineNumber: 658,
        columnNumber: 10
    }, this);
}
_s(I18nProvider, "t2HxYEPL4sx2k9PTTNBe8JHwpGM=");
_c = I18nProvider;
function useI18n() {
    _s1();
    const v = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useContext"])(Ctx);
    if (!v) throw new Error("useI18n outside I18nProvider");
    return v;
}
_s1(useI18n, "vseRKStixtRCAgA7lJDFgCF8qLI=");
var _c;
__turbopack_context__.k.register(_c, "I18nProvider");
if (typeof globalThis.$RefreshHelpers$ === 'object' && globalThis.$RefreshHelpers !== null) {
    __turbopack_context__.k.registerExports(__turbopack_context__.m, globalThis.$RefreshHelpers$);
}
}),
"[project]/src/lib/ui/theme.tsx [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "ThemeProvider",
    ()=>ThemeProvider,
    "useTheme",
    ()=>useTheme
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/jsx-dev-runtime.js [app-client] (ecmascript)");
// SENTINEL theme — dark default (command-deck), light mode. Hand-rolled:
// no new dependencies. Applies the .dark class + persists the choice.
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)");
;
var _s = __turbopack_context__.k.signature(), _s1 = __turbopack_context__.k.signature();
"use client";
;
const Ctx = /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["createContext"])(null);
function pick() {
    if ("TURBOPACK compile-time falsy", 0) //TURBOPACK unreachable
    ;
    const saved = window.localStorage.getItem("sentinel.theme");
    return saved === "light" || saved === "dark" ? saved : "dark";
}
function ThemeProvider({ children }) {
    _s();
    const [theme, setThemeState] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useState"])("dark");
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "ThemeProvider.useEffect": ()=>{
            setThemeState(pick());
        }
    }["ThemeProvider.useEffect"], []);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "ThemeProvider.useEffect": ()=>{
            document.documentElement.classList.toggle("dark", theme === "dark");
            document.documentElement.style.colorScheme = theme;
        }
    }["ThemeProvider.useEffect"], [
        theme
    ]);
    const setTheme = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "ThemeProvider.useCallback[setTheme]": (t)=>{
            setThemeState(t);
            try {
                window.localStorage.setItem("sentinel.theme", t);
            } catch  {
            /* private mode */ }
        }
    }["ThemeProvider.useCallback[setTheme]"], []);
    const toggle = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "ThemeProvider.useCallback[toggle]": ()=>{
            setThemeState({
                "ThemeProvider.useCallback[toggle]": (cur)=>{
                    const next = cur === "dark" ? "light" : "dark";
                    try {
                        window.localStorage.setItem("sentinel.theme", next);
                    } catch  {
                    /* private mode */ }
                    return next;
                }
            }["ThemeProvider.useCallback[toggle]"]);
        }
    }["ThemeProvider.useCallback[toggle]"], []);
    const value = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useMemo"])({
        "ThemeProvider.useMemo[value]": ()=>({
                theme,
                setTheme,
                toggle
            })
    }["ThemeProvider.useMemo[value]"], [
        theme,
        setTheme,
        toggle
    ]);
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(Ctx.Provider, {
        value: value,
        children: children
    }, void 0, false, {
        fileName: "[project]/src/lib/ui/theme.tsx",
        lineNumber: 54,
        columnNumber: 10
    }, this);
}
_s(ThemeProvider, "GtEn/W6TD6QzxoWC1Y3Os1/2hDU=");
_c = ThemeProvider;
function useTheme() {
    _s1();
    const v = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useContext"])(Ctx);
    if (!v) throw new Error("useTheme outside ThemeProvider");
    return v;
}
_s1(useTheme, "vseRKStixtRCAgA7lJDFgCF8qLI=");
var _c;
__turbopack_context__.k.register(_c, "ThemeProvider");
if (typeof globalThis.$RefreshHelpers$ === 'object' && globalThis.$RefreshHelpers !== null) {
    __turbopack_context__.k.registerExports(__turbopack_context__.m, globalThis.$RefreshHelpers$);
}
}),
"[project]/src/lib/ui/toast.tsx [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "ToastProvider",
    ()=>ToastProvider,
    "useToast",
    ()=>useToast
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/jsx-dev-runtime.js [app-client] (ecmascript)");
// SENTINEL toasts — minimal, accessible, reduced-motion safe.
// One viewport, four variants, auto-dismiss with hover pause, RTL-aware.
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$check$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCircle2$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/circle-check.js [app-client] (ecmascript) <export default as CheckCircle2>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$info$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__Info$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/info.js [app-client] (ecmascript) <export default as Info>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__TriangleAlert$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-client] (ecmascript) <export default as TriangleAlert>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/x.js [app-client] (ecmascript) <export default as X>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__XCircle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/circle-x.js [app-client] (ecmascript) <export default as XCircle>");
;
var _s = __turbopack_context__.k.signature(), _s1 = __turbopack_context__.k.signature();
"use client";
;
;
const Ctx = /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["createContext"])(null);
const ICONS = {
    success: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$check$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCircle2$3e$__["CheckCircle2"], {
        className: "size-4 shrink-0 text-[var(--success)]",
        "aria-hidden": true
    }, void 0, false, {
        fileName: "[project]/src/lib/ui/toast.tsx",
        lineNumber: 23,
        columnNumber: 12
    }, ("TURBOPACK compile-time value", void 0)),
    error: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__XCircle$3e$__["XCircle"], {
        className: "size-4 shrink-0 text-[var(--severity-critical)]",
        "aria-hidden": true
    }, void 0, false, {
        fileName: "[project]/src/lib/ui/toast.tsx",
        lineNumber: 24,
        columnNumber: 10
    }, ("TURBOPACK compile-time value", void 0)),
    warning: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__TriangleAlert$3e$__["TriangleAlert"], {
        className: "size-4 shrink-0 text-[var(--severity-high)]",
        "aria-hidden": true
    }, void 0, false, {
        fileName: "[project]/src/lib/ui/toast.tsx",
        lineNumber: 25,
        columnNumber: 12
    }, ("TURBOPACK compile-time value", void 0)),
    info: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$info$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__Info$3e$__["Info"], {
        className: "size-4 shrink-0 text-primary",
        "aria-hidden": true
    }, void 0, false, {
        fileName: "[project]/src/lib/ui/toast.tsx",
        lineNumber: 26,
        columnNumber: 9
    }, ("TURBOPACK compile-time value", void 0))
};
const BORDER = {
    success: "border-s-[3px] border-s-[var(--success)]",
    error: "border-s-[3px] border-s-[var(--severity-critical)]",
    warning: "border-s-[3px] border-s-[var(--severity-high)]",
    info: "border-s-[3px] border-s-primary"
};
function ToastProvider({ children }) {
    _s();
    const [items, setItems] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useState"])([]);
    const seq = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useRef"])(0);
    const timers = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useRef"])(new Map());
    const dismiss = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "ToastProvider.useCallback[dismiss]": (id)=>{
            const t = timers.current.get(id);
            if (t) {
                clearTimeout(t);
                timers.current.delete(id);
            }
            setItems({
                "ToastProvider.useCallback[dismiss]": (cur)=>cur.filter({
                        "ToastProvider.useCallback[dismiss]": (x)=>x.id !== id
                    }["ToastProvider.useCallback[dismiss]"])
            }["ToastProvider.useCallback[dismiss]"]);
        }
    }["ToastProvider.useCallback[dismiss]"], []);
    const push = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "ToastProvider.useCallback[push]": (variant, message)=>{
            const id = ++seq.current;
            setItems({
                "ToastProvider.useCallback[push]": (cur)=>[
                        ...cur.slice(-4),
                        {
                            id,
                            variant,
                            message
                        }
                    ]
            }["ToastProvider.useCallback[push]"]);
            const t = setTimeout({
                "ToastProvider.useCallback[push].t": ()=>dismiss(id)
            }["ToastProvider.useCallback[push].t"], 4600);
            timers.current.set(id, t);
        }
    }["ToastProvider.useCallback[push]"], [
        dismiss
    ]);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "ToastProvider.useEffect": ()=>({
                "ToastProvider.useEffect": ()=>{
                    timers.current.forEach({
                        "ToastProvider.useEffect": (t)=>clearTimeout(t)
                    }["ToastProvider.useEffect"]);
                    timers.current.clear();
                }
            })["ToastProvider.useEffect"]
    }["ToastProvider.useEffect"], []);
    const value = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useMemo"])({
        "ToastProvider.useMemo[value]": ()=>({
                push,
                success: ({
                    "ToastProvider.useMemo[value]": (m)=>push("success", m)
                })["ToastProvider.useMemo[value]"],
                error: ({
                    "ToastProvider.useMemo[value]": (m)=>push("error", m)
                })["ToastProvider.useMemo[value]"],
                info: ({
                    "ToastProvider.useMemo[value]": (m)=>push("info", m)
                })["ToastProvider.useMemo[value]"],
                warning: ({
                    "ToastProvider.useMemo[value]": (m)=>push("warning", m)
                })["ToastProvider.useMemo[value]"]
            })
    }["ToastProvider.useMemo[value]"], [
        push
    ]);
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(Ctx.Provider, {
        value: value,
        children: [
            children,
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                "aria-live": "polite",
                "aria-label": "notifications",
                className: "pointer-events-none fixed inset-x-0 bottom-4 z-[100] flex flex-col items-stretch gap-2 px-4 sm:items-start",
                children: items.map((it)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        role: "status",
                        className: `pointer-events-auto flex w-full max-w-sm items-start gap-2.5 rounded-lg border bg-card px-3.5 py-3 text-sm leading-6 text-card-foreground shadow-[var(--shadow-card)] ${BORDER[it.variant]}`,
                        style: {
                            animation: "toast-in 160ms ease-out"
                        },
                        children: [
                            ICONS[it.variant],
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                className: "flex-1 break-words",
                                children: it.message
                            }, void 0, false, {
                                fileName: "[project]/src/lib/ui/toast.tsx",
                                lineNumber: 96,
                                columnNumber: 13
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                type: "button",
                                onClick: ()=>dismiss(it.id),
                                "aria-label": "close notification",
                                className: "rounded p-0.5 text-muted-foreground transition-colors hover:text-foreground",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__["X"], {
                                    className: "size-3.5",
                                    "aria-hidden": true
                                }, void 0, false, {
                                    fileName: "[project]/src/lib/ui/toast.tsx",
                                    lineNumber: 103,
                                    columnNumber: 15
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/lib/ui/toast.tsx",
                                lineNumber: 97,
                                columnNumber: 13
                            }, this)
                        ]
                    }, it.id, true, {
                        fileName: "[project]/src/lib/ui/toast.tsx",
                        lineNumber: 89,
                        columnNumber: 11
                    }, this))
            }, void 0, false, {
                fileName: "[project]/src/lib/ui/toast.tsx",
                lineNumber: 83,
                columnNumber: 7
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])("style", {
                children: `@keyframes toast-in { from { opacity: 0; transform: translateY(6px);} to { opacity: 1; transform: none;} }
@media (prefers-reduced-motion: reduce) { [role="status"] { animation: none !important; } }`
            }, void 0, false, {
                fileName: "[project]/src/lib/ui/toast.tsx",
                lineNumber: 108,
                columnNumber: 7
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/lib/ui/toast.tsx",
        lineNumber: 80,
        columnNumber: 5
    }, this);
}
_s(ToastProvider, "TFgb+i4OE7FPwTcxljo4o/bRUmQ=");
_c = ToastProvider;
function useToast() {
    _s1();
    const v = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useContext"])(Ctx);
    if (!v) throw new Error("useToast outside ToastProvider");
    return v;
}
_s1(useToast, "vseRKStixtRCAgA7lJDFgCF8qLI=");
var _c;
__turbopack_context__.k.register(_c, "ToastProvider");
if (typeof globalThis.$RefreshHelpers$ === 'object' && globalThis.$RefreshHelpers !== null) {
    __turbopack_context__.k.registerExports(__turbopack_context__.m, globalThis.$RefreshHelpers$);
}
}),
"[project]/src/components/saas/api.ts [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

// Client-side API layer + shared types for the SENTINEL SaaS dashboard
__turbopack_context__.s([
    "ApiError",
    ()=>ApiError,
    "api",
    ()=>api,
    "fmtDate",
    ()=>fmtDate,
    "fmtDuration",
    ()=>fmtDuration
]);
class ApiError extends Error {
    status;
    constructor(status, message){
        super(message);
        this.status = status;
    }
}
async function req(url, init) {
    const res = await fetch(url, {
        ...init,
        headers: {
            "Content-Type": "application/json",
            ...init?.headers || {}
        },
        cache: "no-store"
    });
    const text = await res.text();
    let data = null;
    try {
        data = text ? JSON.parse(text) : null;
    } catch  {
    /* non-json */ }
    if (!res.ok) {
        const msg = data?.error || `فشل الطلب (${res.status})`;
        throw new ApiError(res.status, msg);
    }
    return data;
}
const api = {
    bootstrapStatus: ()=>req("/api/bootstrap"),
    bootstrap: (body)=>req("/api/bootstrap", {
            method: "POST",
            body: JSON.stringify(body)
        }),
    me: ()=>req("/api/me"),
    orgOverview: (orgId)=>req(`/api/orgs/${orgId}`),
    createOrg: (name)=>req("/api/orgs", {
            method: "POST",
            body: JSON.stringify({
                name
            })
        }),
    targets: (orgId)=>req(`/api/targets?orgId=${orgId}`),
    createTarget: (body)=>req("/api/targets", {
            method: "POST",
            body: JSON.stringify(body)
        }),
    deleteTarget: (orgId, id)=>req(`/api/targets/${id}?orgId=${orgId}`, {
            method: "DELETE"
        }),
    scans: (orgId, targetId)=>req(`/api/scans?orgId=${orgId}${targetId ? `&targetId=${targetId}` : ""}`),
    startScan: (body)=>req("/api/scans", {
            method: "POST",
            body: JSON.stringify(body)
        }),
    scanDetail: (orgId, id)=>req(`/api/scans/${id}?orgId=${orgId}`),
    cancelScan: (orgId, id)=>req(`/api/scans/${id}?orgId=${orgId}`, {
            method: "DELETE"
        }),
    scanFindings: (orgId, id, params)=>req(`/api/scans/${id}/findings?orgId=${orgId}${params ? `&${params}` : ""}`),
    scanCoverage: (orgId, id)=>req(`/api/scans/${id}/coverage?orgId=${orgId}`),
    scanTwin: (orgId, id)=>req(`/api/v1/scans/${id}/twin?orgId=${orgId}`),
    findingDetail: (orgId, id)=>req(`/api/findings/${id}?orgId=${orgId}`),
    reports: (orgId)=>req(`/api/reports?orgId=${orgId}`),
    createReport: (body)=>req("/api/reports", {
            method: "POST",
            body: JSON.stringify(body)
        }),
    reportDetail: (orgId, id)=>req(`/api/reports/${id}?orgId=${orgId}`),
    members: (orgId)=>req(`/api/orgs/${orgId}/members`),
    addMember: (orgId, body)=>req(`/api/orgs/${orgId}/members`, {
            method: "POST",
            body: JSON.stringify(body)
        }),
    changeMemberRole: (orgId, mid, role)=>req(`/api/orgs/${orgId}/members/${mid}`, {
            method: "PATCH",
            body: JSON.stringify({
                role
            })
        }),
    removeMember: (orgId, mid)=>req(`/api/orgs/${orgId}/members/${mid}`, {
            method: "DELETE"
        }),
    audit: (orgId)=>req(`/api/audit?orgId=${orgId}`)
};
function fmtDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return d.toLocaleString("ar-LY", {
        dateStyle: "short",
        timeStyle: "medium",
        hour12: false
    });
}
function fmtDuration(sec) {
    if (sec === null || sec === undefined) return "—";
    if (sec < 60) return `${Math.round(sec)}ث`;
    const m = Math.floor(sec / 60);
    const s = Math.round(sec % 60);
    return `${m}د ${s}ث`;
}
if (typeof globalThis.$RefreshHelpers$ === 'object' && globalThis.$RefreshHelpers !== null) {
    __turbopack_context__.k.registerExports(__turbopack_context__.m, globalThis.$RefreshHelpers$);
}
}),
"[project]/src/lib/ui/session.tsx [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "SessionProvider",
    ()=>SessionProvider,
    "useSession",
    ()=>useSession
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/jsx-dev-runtime.js [app-client] (ecmascript)");
// SENTINEL session — client-side session context on top of /api/me.
// Provides the active org (first membership) + role + user, with a hard
// redirect to /login when unauthenticated (the API layer stays the only
// enforcement point; this is UX, not a security boundary).
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/navigation.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$saas$2f$api$2e$ts__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/saas/api.ts [app-client] (ecmascript)");
;
var _s = __turbopack_context__.k.signature(), _s1 = __turbopack_context__.k.signature();
"use client";
;
;
;
const Ctx = /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["createContext"])(null);
function SessionProvider({ children }) {
    _s();
    const [ready, setReady] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useState"])(false);
    const [me, setMe] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useState"])(null);
    const router = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useRouter"])();
    const load = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "SessionProvider.useCallback[load]": async ()=>{
            try {
                const data = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$saas$2f$api$2e$ts__$5b$app$2d$client$5d$__$28$ecmascript$29$__["api"].me();
                setMe(data);
            } catch  {
                setMe(null);
            } finally{
                setReady(true);
            }
        }
    }["SessionProvider.useCallback[load]"], []);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "SessionProvider.useEffect": ()=>{
            void load();
        }
    }["SessionProvider.useEffect"], [
        load
    ]);
    const refresh = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "SessionProvider.useCallback[refresh]": async ()=>{
            try {
                setMe(await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$saas$2f$api$2e$ts__$5b$app$2d$client$5d$__$28$ecmascript$29$__["api"].me());
            } catch  {
                setMe(null);
            }
        }
    }["SessionProvider.useCallback[refresh]"], []);
    const signOut = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useCallback"])({
        "SessionProvider.useCallback[signOut]": async ()=>{
            await fetch("/api/auth/signout", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: "csrfToken=&json=true"
            }).catch({
                "SessionProvider.useCallback[signOut]": ()=>null
            }["SessionProvider.useCallback[signOut]"]);
            setMe(null);
            router.replace("/login");
        }
    }["SessionProvider.useCallback[signOut]"], [
        router
    ]);
    const value = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useMemo"])({
        "SessionProvider.useMemo[value]": ()=>({
                ready,
                me,
                org: me?.orgs?.[0] ?? null,
                role: me?.orgs?.[0]?.role ?? "VIEWER",
                refresh,
                signOut
            })
    }["SessionProvider.useMemo[value]"], [
        ready,
        me,
        refresh,
        signOut
    ]);
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["jsxDEV"])(Ctx.Provider, {
        value: value,
        children: children
    }, void 0, false, {
        fileName: "[project]/src/lib/ui/session.tsx",
        lineNumber: 73,
        columnNumber: 10
    }, this);
}
_s(SessionProvider, "VizcuNUysIuqxiQKYcSosdGfYyI=", false, function() {
    return [
        __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useRouter"]
    ];
});
_c = SessionProvider;
function useSession() {
    _s1();
    const v = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useContext"])(Ctx);
    if (!v) throw new Error("useSession outside SessionProvider");
    return v;
}
_s1(useSession, "vseRKStixtRCAgA7lJDFgCF8qLI=");
var _c;
__turbopack_context__.k.register(_c, "SessionProvider");
if (typeof globalThis.$RefreshHelpers$ === 'object' && globalThis.$RefreshHelpers !== null) {
    __turbopack_context__.k.registerExports(__turbopack_context__.m, globalThis.$RefreshHelpers$);
}
}),
"[project]/node_modules/next/dist/compiled/react/cjs/react-jsx-dev-runtime.development.js [app-client] (ecmascript)", ((__turbopack_context__, module, exports) => {
"use strict";

var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$build$2f$polyfills$2f$process$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = /*#__PURE__*/ __turbopack_context__.i("[project]/node_modules/next/dist/build/polyfills/process.js [app-client] (ecmascript)");
/**
 * @license React
 * react-jsx-dev-runtime.development.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */ "use strict";
"production" !== ("TURBOPACK compile-time value", "development") && function() {
    function getComponentNameFromType(type) {
        if (null == type) return null;
        if ("function" === typeof type) return type.$$typeof === REACT_CLIENT_REFERENCE ? null : type.displayName || type.name || null;
        if ("string" === typeof type) return type;
        switch(type){
            case REACT_FRAGMENT_TYPE:
                return "Fragment";
            case REACT_PROFILER_TYPE:
                return "Profiler";
            case REACT_STRICT_MODE_TYPE:
                return "StrictMode";
            case REACT_SUSPENSE_TYPE:
                return "Suspense";
            case REACT_SUSPENSE_LIST_TYPE:
                return "SuspenseList";
            case REACT_ACTIVITY_TYPE:
                return "Activity";
            case REACT_VIEW_TRANSITION_TYPE:
                return "ViewTransition";
        }
        if ("object" === typeof type) switch("number" === typeof type.tag && console.error("Received an unexpected object in getComponentNameFromType(). This is likely a bug in React. Please file an issue."), type.$$typeof){
            case REACT_PORTAL_TYPE:
                return "Portal";
            case REACT_CONTEXT_TYPE:
                return type.displayName || "Context";
            case REACT_CONSUMER_TYPE:
                return (type._context.displayName || "Context") + ".Consumer";
            case REACT_FORWARD_REF_TYPE:
                var innerType = type.render;
                type = type.displayName;
                type || (type = innerType.displayName || innerType.name || "", type = "" !== type ? "ForwardRef(" + type + ")" : "ForwardRef");
                return type;
            case REACT_MEMO_TYPE:
                return innerType = type.displayName || null, null !== innerType ? innerType : getComponentNameFromType(type.type) || "Memo";
            case REACT_LAZY_TYPE:
                innerType = type._payload;
                type = type._init;
                try {
                    return getComponentNameFromType(type(innerType));
                } catch (x) {}
        }
        return null;
    }
    function testStringCoercion(value) {
        return "" + value;
    }
    function checkKeyStringCoercion(value) {
        try {
            testStringCoercion(value);
            var JSCompiler_inline_result = !1;
        } catch (e) {
            JSCompiler_inline_result = !0;
        }
        if (JSCompiler_inline_result) {
            JSCompiler_inline_result = console;
            var JSCompiler_temp_const = JSCompiler_inline_result.error;
            var JSCompiler_inline_result$jscomp$0 = "function" === typeof Symbol && Symbol.toStringTag && value[Symbol.toStringTag] || value.constructor.name || "Object";
            JSCompiler_temp_const.call(JSCompiler_inline_result, "The provided key is an unsupported type %s. This value must be coerced to a string before using it here.", JSCompiler_inline_result$jscomp$0);
            return testStringCoercion(value);
        }
    }
    function getTaskName(type) {
        if (type === REACT_FRAGMENT_TYPE) return "<>";
        if ("object" === typeof type && null !== type && type.$$typeof === REACT_LAZY_TYPE) return "<...>";
        try {
            var name = getComponentNameFromType(type);
            return name ? "<" + name + ">" : "<...>";
        } catch (x) {
            return "<...>";
        }
    }
    function getOwner() {
        var dispatcher = ReactSharedInternals.A;
        return null === dispatcher ? null : dispatcher.getOwner();
    }
    function UnknownOwner() {
        return Error("react-stack-top-frame");
    }
    function hasValidKey(config) {
        if (hasOwnProperty.call(config, "key")) {
            var getter = Object.getOwnPropertyDescriptor(config, "key").get;
            if (getter && getter.isReactWarning) return !1;
        }
        return void 0 !== config.key;
    }
    function defineKeyPropWarningGetter(props, displayName) {
        function warnAboutAccessingKey() {
            specialPropKeyWarningShown || (specialPropKeyWarningShown = !0, console.error("%s: `key` is not a prop. Trying to access it will result in `undefined` being returned. If you need to access the same value within the child component, you should pass it as a different prop. (https://react.dev/link/special-props)", displayName));
        }
        warnAboutAccessingKey.isReactWarning = !0;
        Object.defineProperty(props, "key", {
            get: warnAboutAccessingKey,
            configurable: !0
        });
    }
    function elementRefGetterWithDeprecationWarning() {
        var componentName = getComponentNameFromType(this.type);
        didWarnAboutElementRef[componentName] || (didWarnAboutElementRef[componentName] = !0, console.error("Accessing element.ref was removed in React 19. ref is now a regular prop. It will be removed from the JSX Element type in a future release."));
        componentName = this.props.ref;
        return void 0 !== componentName ? componentName : null;
    }
    function ReactElement(type, key, props, owner, debugStack, debugTask) {
        var refProp = props.ref;
        type = {
            $$typeof: REACT_ELEMENT_TYPE,
            type: type,
            key: key,
            props: props,
            _owner: owner
        };
        null !== (void 0 !== refProp ? refProp : null) ? Object.defineProperty(type, "ref", {
            enumerable: !1,
            get: elementRefGetterWithDeprecationWarning
        }) : Object.defineProperty(type, "ref", {
            enumerable: !1,
            value: null
        });
        type._store = {};
        Object.defineProperty(type._store, "validated", {
            configurable: !1,
            enumerable: !1,
            writable: !0,
            value: 0
        });
        Object.defineProperty(type, "_debugInfo", {
            configurable: !1,
            enumerable: !1,
            writable: !0,
            value: null
        });
        Object.defineProperty(type, "_debugStack", {
            configurable: !1,
            enumerable: !1,
            writable: !0,
            value: debugStack
        });
        Object.defineProperty(type, "_debugTask", {
            configurable: !1,
            enumerable: !1,
            writable: !0,
            value: debugTask
        });
        Object.freeze && (Object.freeze(type.props), Object.freeze(type));
        return type;
    }
    function jsxDEVImpl(type, config, maybeKey, isStaticChildren, debugStack, debugTask) {
        var children = config.children;
        if (void 0 !== children) if (isStaticChildren) if (isArrayImpl(children)) {
            for(isStaticChildren = 0; isStaticChildren < children.length; isStaticChildren++)validateChildKeys(children[isStaticChildren]);
            Object.freeze && Object.freeze(children);
        } else console.error("React.jsx: Static children should always be an array. You are likely explicitly calling React.jsxs or React.jsxDEV. Use the Babel transform instead.");
        else validateChildKeys(children);
        if (hasOwnProperty.call(config, "key")) {
            children = getComponentNameFromType(type);
            var keys = Object.keys(config).filter(function(k) {
                return "key" !== k;
            });
            isStaticChildren = 0 < keys.length ? "{key: someKey, " + keys.join(": ..., ") + ": ...}" : "{key: someKey}";
            didWarnAboutKeySpread[children + isStaticChildren] || (keys = 0 < keys.length ? "{" + keys.join(": ..., ") + ": ...}" : "{}", console.error('A props object containing a "key" prop is being spread into JSX:\n  let props = %s;\n  <%s {...props} />\nReact keys must be passed directly to JSX without using spread:\n  let props = %s;\n  <%s key={someKey} {...props} />', isStaticChildren, children, keys, children), didWarnAboutKeySpread[children + isStaticChildren] = !0);
        }
        children = null;
        void 0 !== maybeKey && (checkKeyStringCoercion(maybeKey), children = "" + maybeKey);
        hasValidKey(config) && (checkKeyStringCoercion(config.key), children = "" + config.key);
        if ("key" in config) {
            maybeKey = {};
            for(var propName in config)"key" !== propName && (maybeKey[propName] = config[propName]);
        } else maybeKey = config;
        children && defineKeyPropWarningGetter(maybeKey, "function" === typeof type ? type.displayName || type.name || "Unknown" : type);
        return ReactElement(type, children, maybeKey, getOwner(), debugStack, debugTask);
    }
    function validateChildKeys(node) {
        isValidElement(node) ? node._store && (node._store.validated = 1) : "object" === typeof node && null !== node && node.$$typeof === REACT_LAZY_TYPE && ("fulfilled" === node._payload.status ? isValidElement(node._payload.value) && node._payload.value._store && (node._payload.value._store.validated = 1) : node._store && (node._store.validated = 1));
    }
    function isValidElement(object) {
        return "object" === typeof object && null !== object && object.$$typeof === REACT_ELEMENT_TYPE;
    }
    var React = __turbopack_context__.r("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)"), REACT_ELEMENT_TYPE = Symbol.for("react.transitional.element"), REACT_PORTAL_TYPE = Symbol.for("react.portal"), REACT_FRAGMENT_TYPE = Symbol.for("react.fragment"), REACT_STRICT_MODE_TYPE = Symbol.for("react.strict_mode"), REACT_PROFILER_TYPE = Symbol.for("react.profiler"), REACT_CONSUMER_TYPE = Symbol.for("react.consumer"), REACT_CONTEXT_TYPE = Symbol.for("react.context"), REACT_FORWARD_REF_TYPE = Symbol.for("react.forward_ref"), REACT_SUSPENSE_TYPE = Symbol.for("react.suspense"), REACT_SUSPENSE_LIST_TYPE = Symbol.for("react.suspense_list"), REACT_MEMO_TYPE = Symbol.for("react.memo"), REACT_LAZY_TYPE = Symbol.for("react.lazy"), REACT_ACTIVITY_TYPE = Symbol.for("react.activity"), REACT_VIEW_TRANSITION_TYPE = Symbol.for("react.view_transition"), REACT_CLIENT_REFERENCE = Symbol.for("react.client.reference"), ReactSharedInternals = React.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE, hasOwnProperty = Object.prototype.hasOwnProperty, isArrayImpl = Array.isArray, createTask = console.createTask ? console.createTask : function() {
        return null;
    };
    React = {
        react_stack_bottom_frame: function(callStackForError) {
            return callStackForError();
        }
    };
    var specialPropKeyWarningShown;
    var didWarnAboutElementRef = {};
    var unknownOwnerDebugStack = React.react_stack_bottom_frame.bind(React, UnknownOwner)();
    var unknownOwnerDebugTask = createTask(getTaskName(UnknownOwner));
    var didWarnAboutKeySpread = {};
    exports.Fragment = REACT_FRAGMENT_TYPE;
    exports.jsxDEV = function(type, config, maybeKey, isStaticChildren) {
        var trackActualOwner = 1e4 > ReactSharedInternals.recentlyCreatedOwnerStacks++;
        if (trackActualOwner) {
            var previousStackTraceLimit = Error.stackTraceLimit;
            Error.stackTraceLimit = 10;
            var debugStackDEV = Error("react-stack-top-frame");
            Error.stackTraceLimit = previousStackTraceLimit;
        } else debugStackDEV = unknownOwnerDebugStack;
        return jsxDEVImpl(type, config, maybeKey, isStaticChildren, debugStackDEV, trackActualOwner ? createTask(getTaskName(type)) : unknownOwnerDebugTask);
    };
}();
}),
"[project]/node_modules/next/dist/compiled/react/jsx-dev-runtime.js [app-client] (ecmascript)", ((__turbopack_context__, module, exports) => {
"use strict";

var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$build$2f$polyfills$2f$process$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = /*#__PURE__*/ __turbopack_context__.i("[project]/node_modules/next/dist/build/polyfills/process.js [app-client] (ecmascript)");
'use strict';
if ("TURBOPACK compile-time falsy", 0) //TURBOPACK unreachable
;
else {
    module.exports = __turbopack_context__.r("[project]/node_modules/next/dist/compiled/react/cjs/react-jsx-dev-runtime.development.js [app-client] (ecmascript)");
}
}),
"[project]/node_modules/lucide-react/dist/esm/shared/src/utils.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "hasA11yProp",
    ()=>hasA11yProp,
    "mergeClasses",
    ()=>mergeClasses,
    "toCamelCase",
    ()=>toCamelCase,
    "toKebabCase",
    ()=>toKebabCase,
    "toPascalCase",
    ()=>toPascalCase
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ const toKebabCase = (string)=>string.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
const toCamelCase = (string)=>string.replace(/^([A-Z])|[\s-_]+(\w)/g, (match, p1, p2)=>p2 ? p2.toUpperCase() : p1.toLowerCase());
const toPascalCase = (string)=>{
    const camelCase = toCamelCase(string);
    return camelCase.charAt(0).toUpperCase() + camelCase.slice(1);
};
const mergeClasses = (...classes)=>classes.filter((className, index, array)=>{
        return Boolean(className) && className.trim() !== "" && array.indexOf(className) === index;
    }).join(" ").trim();
const hasA11yProp = (props)=>{
    for(const prop in props){
        if (prop.startsWith("aria-") || prop === "role" || prop === "title") {
            return true;
        }
    }
};
;
 //# sourceMappingURL=utils.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/defaultAttributes.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>defaultAttributes
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var defaultAttributes = {
    xmlns: "http://www.w3.org/2000/svg",
    width: 24,
    height: 24,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round",
    strokeLinejoin: "round"
};
;
 //# sourceMappingURL=defaultAttributes.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/Icon.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>Icon
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$defaultAttributes$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/defaultAttributes.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/shared/src/utils.js [app-client] (ecmascript)");
;
;
;
const Icon = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["forwardRef"])(({ color = "currentColor", size = 24, strokeWidth = 2, absoluteStrokeWidth, className = "", children, iconNode, ...rest }, ref)=>(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["createElement"])("svg", {
        ref,
        ...__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$defaultAttributes$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"],
        width: size,
        height: size,
        stroke: color,
        strokeWidth: absoluteStrokeWidth ? Number(strokeWidth) * 24 / Number(size) : strokeWidth,
        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["mergeClasses"])("lucide", className),
        ...!children && !(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["hasA11yProp"])(rest) && {
            "aria-hidden": "true"
        },
        ...rest
    }, [
        ...iconNode.map(([tag, attrs])=>(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["createElement"])(tag, attrs)),
        ...Array.isArray(children) ? children : [
            children
        ]
    ]));
;
 //# sourceMappingURL=Icon.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/createLucideIcon.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>createLucideIcon
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/shared/src/utils.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$Icon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/Icon.js [app-client] (ecmascript)");
;
;
;
const createLucideIcon = (iconName, iconNode)=>{
    const Component = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["forwardRef"])(({ className, ...props }, ref)=>(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["createElement"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$Icon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"], {
            ref,
            iconNode,
            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["mergeClasses"])(`lucide-${(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["toKebabCase"])((0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["toPascalCase"])(iconName))}`, `lucide-${iconName}`, className),
            ...props
        }));
    Component.displayName = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$shared$2f$src$2f$utils$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["toPascalCase"])(iconName);
    return Component;
};
;
 //# sourceMappingURL=createLucideIcon.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/icons/circle-check.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "__iconNode",
    ()=>__iconNode,
    "default",
    ()=>CircleCheck
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/createLucideIcon.js [app-client] (ecmascript)");
;
const __iconNode = [
    [
        "circle",
        {
            cx: "12",
            cy: "12",
            r: "10",
            key: "1mglay"
        }
    ],
    [
        "path",
        {
            d: "m9 12 2 2 4-4",
            key: "dzmm74"
        }
    ]
];
const CircleCheck = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"])("circle-check", __iconNode);
;
 //# sourceMappingURL=circle-check.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/icons/circle-check.js [app-client] (ecmascript) <export default as CheckCircle2>", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "CheckCircle2",
    ()=>__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$check$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"]
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$check$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/circle-check.js [app-client] (ecmascript)");
}),
"[project]/node_modules/lucide-react/dist/esm/icons/info.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "__iconNode",
    ()=>__iconNode,
    "default",
    ()=>Info
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/createLucideIcon.js [app-client] (ecmascript)");
;
const __iconNode = [
    [
        "circle",
        {
            cx: "12",
            cy: "12",
            r: "10",
            key: "1mglay"
        }
    ],
    [
        "path",
        {
            d: "M12 16v-4",
            key: "1dtifu"
        }
    ],
    [
        "path",
        {
            d: "M12 8h.01",
            key: "e9boi3"
        }
    ]
];
const Info = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"])("info", __iconNode);
;
 //# sourceMappingURL=info.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/icons/info.js [app-client] (ecmascript) <export default as Info>", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "Info",
    ()=>__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$info$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"]
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$info$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/info.js [app-client] (ecmascript)");
}),
"[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "__iconNode",
    ()=>__iconNode,
    "default",
    ()=>TriangleAlert
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/createLucideIcon.js [app-client] (ecmascript)");
;
const __iconNode = [
    [
        "path",
        {
            d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3",
            key: "wmoenq"
        }
    ],
    [
        "path",
        {
            d: "M12 9v4",
            key: "juzpu7"
        }
    ],
    [
        "path",
        {
            d: "M12 17h.01",
            key: "p32p05"
        }
    ]
];
const TriangleAlert = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"])("triangle-alert", __iconNode);
;
 //# sourceMappingURL=triangle-alert.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-client] (ecmascript) <export default as TriangleAlert>", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "TriangleAlert",
    ()=>__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"]
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-client] (ecmascript)");
}),
"[project]/node_modules/lucide-react/dist/esm/icons/x.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "__iconNode",
    ()=>__iconNode,
    "default",
    ()=>X
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/createLucideIcon.js [app-client] (ecmascript)");
;
const __iconNode = [
    [
        "path",
        {
            d: "M18 6 6 18",
            key: "1bl5f8"
        }
    ],
    [
        "path",
        {
            d: "m6 6 12 12",
            key: "d8bk6v"
        }
    ]
];
const X = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"])("x", __iconNode);
;
 //# sourceMappingURL=x.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/icons/x.js [app-client] (ecmascript) <export default as X>", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "X",
    ()=>__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"]
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/x.js [app-client] (ecmascript)");
}),
"[project]/node_modules/lucide-react/dist/esm/icons/circle-x.js [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "__iconNode",
    ()=>__iconNode,
    "default",
    ()=>CircleX
]);
/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/createLucideIcon.js [app-client] (ecmascript)");
;
const __iconNode = [
    [
        "circle",
        {
            cx: "12",
            cy: "12",
            r: "10",
            key: "1mglay"
        }
    ],
    [
        "path",
        {
            d: "m15 9-6 6",
            key: "1uzhvr"
        }
    ],
    [
        "path",
        {
            d: "m9 9 6 6",
            key: "z0biqf"
        }
    ]
];
const CircleX = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$createLucideIcon$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"])("circle-x", __iconNode);
;
 //# sourceMappingURL=circle-x.js.map
}),
"[project]/node_modules/lucide-react/dist/esm/icons/circle-x.js [app-client] (ecmascript) <export default as XCircle>", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "XCircle",
    ()=>__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"]
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$x$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/circle-x.js [app-client] (ecmascript)");
}),
"[project]/node_modules/next/navigation.js [app-client] (ecmascript)", ((__turbopack_context__, module, exports) => {

module.exports = __turbopack_context__.r("[project]/node_modules/next/dist/client/components/navigation.js [app-client] (ecmascript)");
}),
]);

//# sourceMappingURL=_44b824d9._.js.map