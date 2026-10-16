<!-- PROVENANCE (banking note, NOT part of the original):
     Received verbatim from the supervisor on 2026-10-17 (the session following
     task 68, where the 12-axis original list was requested and proven
     unrecoverable from any committed record — twice). Banked here to end the
     provenance-loss problem permanently. Content is transcribed faithfully
     from the supervisor's message; IM table-rendering artifacts were
     normalized to markdown tables, formulas kept as received. This file is
     THE authoritative axis reference: per the standing clause, the original
     tables supersede any derived contract at any station boundary. -->

# المواصفة الهندسية الكاملة — المحاور الاثنا عشر

---

## المحور الأول: محرك تنفيذ الرسوم البيانية اللا دورية

### 1.1 التعريف الشكلي الموسّع

المحرك يُعرَّف كخُماسي موسّع:

```
G = (V, E, φ, ψ, Ω, Σ, Π, Δ)
```

| الرمز | الدلالة | المجال |
|---|---|---|
| V | العُقد الإجرائية | مجموعة محدودة، \|V\| ≤ 10⁶ |
| E | علاقة الاعتمادية الاتجاهية | E ⊆ V × V، لا دورية |
| φ | دالة التكلفة المتجهية | φ: V → ℝ⁺ × ℝ⁺ × ℝ⁺ |
| ψ | دالة التحقق الشرطي | ψ: V → {0, 1} |
| Ω | دالة الترتيب الطوبولوجي | Ω: V → ℕ |
| Σ | أبجدية الأحداث | Σ = {σ₁, …, σₙ} |
| Π | دالة الإسقاط على الأبعاد | Π: V → ℝᵈ, d = 17 |
| Δ | مؤثر الانتقال | Δ: V × S → V × S |

### 1.2 شروط الصحة (Well-Formedness Conditions)

```
(W1) ∀v ∈ V: ψ(v) ∈ {0, 1}                     — ثنائية التحقق
(W2) ∀(u,v) ∈ E: Ω(u) < Ω(v)                    — رتابة الترتيب
(W3) ∀v ∈ V: ∃ مسار من v₀ إلى v                  — قابلية الوصول
(W4) ∄ دورة في G                                 — اللادورية
(W5) ∀v ∈ V: φ(v)₁ + φ(v)₂ + φ(v)₃ > 0         — التكلفة موجبة
(W6) ∀v ∈ V: |Π(v)| = d                          — ثبات البُعد
```

### 1.3 خوارزمية الترتيب الطوبولوجي

Kahn's Algorithm المُحسَّن:

```
المدخل: G = (V, E)
المخرج: ترتيب طوبولوجي σ

1. احسب in-degree لكل عقدة: O(|V| + |E|)
2. ضع العُقد ذات in-degree = 0 في طابور Q
3. بينما Q ≠ ∅:
   a. v ← Q.dequeue()
   b. σ.append(v)
   c. لكل u ∈ Adj(v):
      i.   in-degree(u) -= 1
      ii.  إذا in-degree(u) = 0: Q.enqueue(u)
4. إذا |σ| < |V|: أبلغ عن دورة (يستحيل حسب W4)
```

التعقيد: Θ(|V| + |E|) زمن، Θ(|V|) مكان.

### 1.4 التقسيم الطبقي (Layered Decomposition)

يُعرَّف الطول الأقصى للمسار (Longest Path Length):

```
L(v) = max{ L(u) + 1 : (u, v) ∈ E } ∪ {0}
```

تُقسَّم العُقد إلى طبقات:

```
Lᵢ = { v ∈ V : L(v) = i }
```

خاصية التوازي: العُقد داخل Lᵢ مستقلة زمنيًا، قابلة للتنفيذ المتوازي.

### 1.5 التنفيذ المتوازي

نموذج BSP (Bulk Synchronous Parallel):

```
لكل طبقة Lᵢ:
   ├── Superstep 1: توزيع العُقد على C أنوية
   ├── Superstep 2: تنفيذ متوازي
   ├── Superstep 3: Barrier Synchronization
   └── Superstep 4: دمج النتائج
```

التعقيد الزمني الكلي:

```
T(G, C) = Σᵢ ⌈|Lᵢ| / C⌉ · τ_op + k · τ_barrier
```

حيث:

- τ_op = زمن العملية الواحدة
- τ_barrier = زمن الحاجز
- k = عدد الطبقات

كفاءة التوازي:

```
E_p = T_serial / (C · T_parallel) ∈ [0, 1]
```

### 1.6 التفريع التخميني

نموذج Copy-on-Write للسياق:

```
عند تفريع v إلى {v₁, v₂, …, vₘ}:
   ├── Context_snapshot = PCS.clone(COW)
   ├── لكل vᵢ: نفّذ على نسخة معزولة
   ├── قيّم كل فرع بـ V(s) (دالة القيمة)
   └── اختر الفرع بـ argmax V(s)
```

معيار الدمج:

```
Merge(v₁, v₂) = v* حيث V(v*) = max{V(v₁), V(v₂)}
```

### 1.7 التقليم التكيفي

قاعدة التقليم:

```
إذا فرع f فشل في k عقدة متتالية (ψ = 0):
   ├── Prune(f)
   ├── سجّل في Boundary Log
   └── حرّر الموارد
```

العتبة الديناميكية:

```
k_adaptive = ⌈log₂(|V|)⌉ · (1 + ε)   حيث ε ∈ [0, 0.5]
```

### 1.8 واجهة برمجية (Interface Contract)

```
interface ExecutionGraph:
    def add_node(v: Node) -> NodeId
    def add_edge(u: NodeId, v: NodeId) -> EdgeId
    def topological_sort() -> List[NodeId]
    def layer_decompose() -> List[List[NodeId]]
    def execute_parallel(concurrency: int) -> ExecutionTrace
    def prune(branch_id: BranchId) -> PruningRecord
    def snapshot() -> GraphSnapshot
    def restore(snapshot: GraphSnapshot) -> void
```

تعقيد الواجهة:

| العملية | التعقيد |
|---|---|
| add_node | O(1) amortized |
| add_edge | O(1) amortized |
| topological_sort | O(V + E) |
| layer_decompose | O(V + E) |
| execute_parallel | O((V + E) / C) |
| snapshot | O(V + E) |
| restore | O(V + E) |

---

## المحور الثاني: آلة الحالة الرسمية للتحقق

### 2.1 التعريف الشكلي الكامل

```
M = (S, Σ, δ, s₀, F, Λ, Γ, Θ)
```

| الرمز | الدلالة |
|---|---|
| S | مجموعة الحالات المحدودة |
| Σ | أبجدية الأحداث |
| δ | دالة الانتقال: S × Σ → S × A |
| s₀ | الحالة الابتدائية |
| F | حالات القبول |
| Λ | دالة إسقاط المتجهات: S → ℝ⁴ |
| Γ | دالة القيود: S → 2^C |
| Θ | دالة التكلفة التراكمية |

### 2.2 حالات الآلة

```
S = {
    s_init,        — الحالة الابتدائية
    s_recon,       — المراقبة الخارجية
    s_foothold,    — الوصول الأولي
    s_elevation,   — رفع الصلاحيات
    s_traversal,   — الانتقال العرضي
    s_objective,   — تحقيق الهدف
    s_exfiltration — استخراج البيانات
}
```

### 2.3 دالة الانتقال التفصيلية

```
δ(s, σ) = (s', a) حيث:

δ(s_init, σ_start)       = (s_recon, a_scan)
δ(s_recon, σ_surface)    = (s_recon, a_map)
δ(s_recon, σ_vuln)       = (s_foothold, a_enter)
δ(s_foothold, σ_priv)    = (s_elevation, a_escalate)
δ(s_foothold, σ_creds)   = (s_traversal, a_move)
δ(s_elevation, σ_creds)  = (s_traversal, a_move)
δ(s_traversal, σ_target) = (s_objective, a_achieve)
δ(s_objective, σ_data)   = (s_exfiltration, a_extract)
```

### 2.4 القيود الرياضية

```
(C1) Irreversibility:  ∀s ∈ {s_elevation, s_objective, s_exfiltration}:
                        ∄ σ: δ(s, σ) → s' حيث L(s') < L(s)
(C2) Monotonicity:     Access(t₁) ≤ Access(t₂) ∀t₁ < t₂
(C3) Trade-off:        Stealth(s) + Coverage(s) ≤ 1 ∀s ∈ S
(C4) Determinism:      ∀(s, σ): |{δ(s, σ)}| = 1
(C5) Reachability:     ∀s ∈ F: ∃ مسار من s₀ إلى s
(C6) Safety:           DetectionRisk(s) ≤ θ_max ∀s ∈ S
```

### 2.5 دالة القيمة (Value Function)

```
V(s) = Σᵢ wᵢ · fᵢ(s)
```

حيث:

- f₁ = Access(s) — درجة الوصول
- f₂ = Persistence(s) — درجة الثبات
- f₃ = Stealth(s) — معامل التخفي
- f₄ = Coverage(s) — معامل التغطية

قيد التطبيع: Σwᵢ = 1, wᵢ ≥ 0.

### 2.6 البحث الاستدلالي (A*)

دالة التقييم:

```
f(n) = g(n) + h(n)
```

حيث:

- g(n) = التكلفة الفعلية من s₀ إلى n
- h(n) = الاستدلال المسموح (Admissible Heuristic)

الاستدلال المسموح:

```
h(n) = max{ V(s_target) - V(s_n), 0 }
```

خاصية الاتساق (Consistency):

```
h(n) ≤ c(n, n') + h(n')   ∀n, n'
```

### 2.7 التعقيد الحسابي

| العملية | التعقيد |
|---|---|
| δ evaluation | O(1) |
| V(s) computation | O(\|S\|) |
| A* search | O(b^d) حيث b = معامل التفريع، d = العمق |
| Optimal path | O(\|S\| log \|S\| + \|E_s\|) |

### 2.8 واجهة برمجية

```
interface StateMachine:
    def transition(state: State, event: Event) -> (State, Action)
    def is_accepting(state: State) -> bool
    def value(state: State) -> float
    def constraints(state: State) -> Set[Constraint]
    def optimal_path(start: State, goal: State) -> List[Action]
    def replay(trace: ExecutionTrace) -> StateSequence
    def verify_invariants() -> InvariantReport
```

---

## المحور الثالث: إدارة سياق الجلسة الموزّع

### 3.1 البنية الرياضية

مخزن السياق الدائم (PCS):

```
PCS = (K, V, T, H, M, R)
```

| الرمز | الدلالة | البنية |
|---|---|---|
| K | مفاتيح مُجزّأة BLAKE3 | {0,1}* → {0,1}^256 |
| V | قيم مُسلسَلة MessagePack | |
| T | طوابع زمنية Lamport Clock | ℕ |
| H | سجل التجزئة Merkle Tree | |
| M | بيانات وصفية Metadata Map | |
| R | مراجع Reference Graph | |

### 3.2 نموذج الاتساق

تصنيف العمليات:

```
O = O_critical ∪ O_diagnostic
```

ضمانات O_critical: ACID

```
(A) Atomicity:   إما كل التغييرات أو لا شيء
(C) Consistency: الحالة تنتقل من صحيحة إلى صحيحة
(I) Isolation:   العمليات المتزامنة معزولة
(D) Durability:  التغييرات المُلتزمة دائمة
```

ضمانات O_diagnostic: BASE

```
(B) Basically Available
(S) Soft state
(E) Eventual consistency
```

### 3.3 Lamport Timestamps

تعريف:

```
LT: Event → ℕ

قواعد التحديث:
(R1) عند حدث محلي: LT(e) = LT(prev) + 1
(R2) عند إرسال رسالة: LT(send) = LT(prev) + 1، أرفق LT
(R3) عند استقبال رسالة: LT(recv) = max(LT(local), LT(msg)) + 1
```

خاصية الترتيب السببي:

```
e₁ → e₂ ⟹ LT(e₁) < LT(e₂)
```

### 3.4 Vector Clocks (بديل دقيق)

تعريف:

```
VC: Event → ℕ^n   حيث n = عدد الوكلاء

قواعد:
(R1) VC_i[i] += 1 عند حدث محلي
(R2) VC_i[j] = max(VC_i[j], VC_msg[j]) عند استقبال
```

خاصية التزامن:

```
e₁ ∥ e₂ ⟺ VC(e₁) ⊥ VC(e₂)
```

### 3.5 Merkle Tree للتحقق

البناء:

```
Leaf(i) = H(data_i)
Node(i, j) = H(Node(i, k) || Node(k+1, j))
Root = Node(1, n)
```

إثبات الانتماء:

```
MerkleProof(leaf, root) = {sibling_hashes}
التحقق: O(log n) hash operations
```

### 3.6 CRDT للتزامن

نوع Counter:

```
State: (ℕ^n, ℕ^n)   — (increments, decrements)
Merge: pointwise max
Convergence: لجميع النسخ المتماثلة
```

نوع Set (OR-Set):

```
State: Set[(Element, UniqueTag)]
Add(e): أضف (e, tag_new)
Remove(e): احذف جميع (e, *)
Merge: union
```

### 3.7 Time-Travel Query

نموذج MVCC (Multi-Version Concurrency Control):

```
Version: (key, value, timestamp, txn_id)
Query(key, t): أحدث قيمة حيث timestamp ≤ t
```

التعقيد: O(log V) مع فهرس B-tree على الزمن.

### 3.8 واجهة برمجية

```
interface ContextStore:
    def write(key: Key, value: Value, consistency: ConsistencyLevel) -> TxId
    def read(key: Key, consistency: ConsistencyLevel) -> Value
    def read_at(key: Key, timestamp: LamportTime) -> Value
    def snapshot() -> ContextSnapshot
    def restore(snapshot: ContextSnapshot) -> void
    def merge(remote: ContextStore, strategy: MergeStrategy) -> MergeReport
    def verify_integrity() -> IntegrityReport
    def merkle_root() -> Hash
    def prove_inclusion(key: Key) -> MerkleProof
```

---

## المحور الرابع: توليف قنوات الاتصال

### 4.1 النموذج السداسي الموسّع

```
C = (T, H, P, E, D, F, Ψ, Φ)
```

| الرمز | الدلالة | المجال |
|---|---|---|
| T | الناقل | {HTTP/2, WS, DNS, SMB, IPC, QUIC} |
| H | متجه الترويسات | Map[String, String] |
| P | الحمولة | ByteString |
| E | دالة التشفير | AEAD |
| D | الانضباط الزمني | Temporal Distribution |
| F | البصمة | Fingerprint Vector |
| Ψ | دالة القياس الطيفي | Ψ: C → Spectrum |
| Φ | دالة التقييس | Φ: C → Standardized Form |

### 4.2 التقارب الاحتمالي

شرط التخفي:

```
D_KL(P_channel ‖ P_baseline) < ε
```

حيث D_KL تباعد كولباك-ليبلر:

```
D_KL(P ‖ Q) = Σₓ P(x) · log(P(x) / Q(x))
```

حدود عملية: ε ∈ [0.01, 0.05] لضمان عدم الكشف الإحصائي.

### 4.3 سلسلة ماركوف للأنماط الزمنية

تعريف:

```
P(t_{i+1} | t_i, t_{i-1}, …, t_{i-k}) = P(t_{i+1} | t_i)
```

(خاصية ماركوف من الرتبة الأولى).

تقدير المعاملات:

```
P(t_{i+1} = j | t_i = i) = N_{ij} / Σ_k N_{ik}
```

حيث N_{ij} عدد الانتقالات من i إلى j.

اختبار الصلاحية: χ² test للتحقق من خاصية ماركوف.

### 4.4 التحليل الطيفي العكسي

التحويل السريع فورييه (FFT):

```
X(f) = Σₙ x(n) · e^{-j2πfn/N}
```

كشف الدورية:

```
إذا |X(f₀)| > θ لبعض f₀: نمط دوري مكشوف
```

الإخفاء الطيفي: أضف ضوضاء N(f) بحيث:

```
|X(f) + N(f)| ~ Uniform(0, P_max)
```

### 4.5 توزيع بواسون غير المتجانس

دالة الكثافة:

```
λ(t) = λ₀ · (1 + α · sin(ωt + φ))
```

توليد الأحداث: عبر Thinning Algorithm:

```
1. λ_max = max_t λ(t)
2. t = 0
3. بينما t < T:
   a. t += Exp(λ_max)   — عينة أسية
   b. إذا U(0,1) ≤ λ(t) / λ_max: أبلغ عن حدث
```

### 4.6 الاهتزاز (Jitter)

النموذج:

```
t_actual = t_base · U(1-γ, 1+γ)
```

حيث U(a,b) توزيع منتظم على [a,b].

معامل الاهتزاز الأمثل:

```
γ* = argmin_γ [ D_KL(P_jittered ‖ P_baseline) ]
```

قيمة عملية: γ ∈ [0.3, 0.5].

### 4.7 التشفير متعدد الطبقات

AEAD (Authenticated Encryption with Associated Data):

```
E: (K, N, A, P) → (C, T)
D: (K, N, A, C, T) → P أو ⊥
```

حيث:

- K = مفتاح 256-bit
- N = nonce 96-bit
- A = بيانات مصاحبة
- P = النص الأصلي
- C = النص المشفر
- T = وسم المصادقة

الخوارزميات المدعومة:

| الخوارزمية | السرعة | الأمان |
|---|---|---|
| ChaCha20-Poly1305 | عالية | 256-bit |
| AES-256-GCM | عالية (مع AES-NI) | 256-bit |
| XChaCha20-Poly1305 | عالية | 256-bit |

### 4.8 تبادل المفاتيح

X25519 (ECDH على Curve25519):

```
Alice: a ∈ ℤ_q، A = a·G
Bob:   b ∈ ℤ_q، B = b·G
Shared: S = a·B = b·A = ab·G
```

HKDF-SHA256 للاشتقاق:

```
PRK = HMAC-SHA256(salt, IKM)
OKM = HMAC-SHA256(PRK, info || 0x01)
```

### 4.9 تدوير المفاتيح

سياسة التدوير:

```
Rotate(K) إذا:
   ├── عدد الجلسات ≥ N_max
   ├── الزمن المنقضي ≥ T_max
   └── عدد البايتات ≥ B_max
```

PFS (Perfect Forward Secrecy):

```
K_session = KDF(K_ephemeral, nonce)
K_ephemeral يُحذف بعد الجلسة
```

### 4.10 القنوات المتعددة

HTTP/2 Multiplexing:

```
Stream ID: 31-bit
Frame: (Length, Type, Flags, StreamID, Payload)
```

WebSocket Full-Duplex:

```
Frame: (FIN, RSV, Opcode, Mask, PayloadLen, MaskKey, Payload)
Ping/Pong: للتحقق من الاتصال
```

DNS Tunneling:

```
TXT Record: Base32-encoded payload
CNAME Record: للتحويل
Query: <encoded>.domain.com
```

التعقيد: O(payload_size / max_query_size) استعلامات.

### 4.11 واجهة برمجية

```
interface CommunicationChannel:
    def open(transport: TransportType, config: ChannelConfig) -> ChannelId
    def send(channel: ChannelId, payload: ByteString, options: SendOptions) -> SendReceipt
    def receive(channel: ChannelId, timeout: Duration) -> ByteString
    def close(channel: ChannelId) -> void
    def fingerprint(channel: ChannelId) -> FingerprintVector
    def measure_spectrum(channel: ChannelId) -> Spectrum
    def compute_kl_divergence(channel: ChannelId, baseline: Baseline) -> float
    def rotate_keys(channel: ChannelId, policy: RotationPolicy) -> KeyRotationReport
```

---

## المحور الخامس: اجتياز طبقات التنفيذ

### 5.1 نموذج الطبقات

```
L₀: Hardware Layer        (CPU, MMU, TPM, IOMMU)
L₁: Hypervisor Layer      (Type-1/Type-2, VBS)
L₂: Kernel Layer          (Ring 0, System Calls)
L₃: System Services       (Ring 0 → User transition)
L₄: User-mode APIs        (Win32/NT/POSIX)
L₅: Application Layer     (Managed Runtimes)
L₆: Virtualization Layer  (Containers, Sandboxes)
```

### 5.2 تقنيات الاجتياز — المصطلحات الهندسية

#### 5.2.1 الاستدعاء المباشر للنواة

التعريف: تجاوز طبقة ntdll.dll بالانتقال إلى تعليمة syscall مباشرة.

البنية:

```
mov r10, rcx
mov eax, SSN
syscall
ret
```

مشكلة: SSN يتغير بين إصدارات Windows.

الحل: إعادة بناء كعب Syscall (Syscall Stub Reconstruction):

```
1. اقرأ ntdll.dll من الذاكرة
2. ابحث عن نمط: mov r10, rcx; mov eax, ?
3. استخرج SSN من البايت 4
4. أنشئ stub مخصص
```

التعقيد: O(|ntdll|) مسح نمطي.

#### 5.2.2 إعادة توجيه معالجة الاستثناءات

VEH (Vectored Exception Handling):

```
PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
```

الاستخدام: تسجيل معالج يُنفّذ قبل SEH، لتنفيذ شيفرة عند استثناء مقصود.

#### 5.2.3 حقن APC

APC (Asynchronous Procedure Call):

```
QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)
```

الشرط: الخيط الهدف في حالة Alertable Wait.

#### 5.2.4 تجويف العملية

Process Hollowing:

```
1. CreateProcess(SUSPENDED)
2. NtUnmapViewOfSection
3. VirtualAllocEx
4. WriteProcessMemory
5. SetThreadContext
6. ResumeThread
```

#### 5.2.5 اختطاف تنفيذ الخيط

Thread Execution Hijacking:

```
1. SuspendThread
2. GetThreadContext
3. Modify RIP/EIP
4. SetThreadContext
5. ResumeThread
```

#### 5.2.6 دوس الوحدات

Module Stomping:

```
1. LoadLibrary(legitimate.dll)
2. VirtualProtect(RW)
3. WriteProcessMemory(payload)
4. VirtualProtect(RX)
5. Execute
```

#### 5.2.7 تزوير مكدس الاستدعاء

Call Stack Spoofing:

```
الهدف: جعل RIP مشروعًا في سجل المكدس

التقنية:
1. أنشئ إطارات مكدس وهمية
2. استخدم ROP gadgets للانتقال
3. أعد المكدس الأصلي بعد التنفيذ
```

#### 5.2.8 تشفير الذاكرة أثناء السكون

Sleep-time Memory Encryption:

```
1. قبل Sleep: VirtualProtect(RW)
2. شفّر الحمولة بمفتاح جلسة
3. Sleep
4. بعد الاستيقاظ: فك التشفير
5. VirtualProtect(RX)
```

الخوارزمية: AES-128-CTR أو ChaCha20.

#### 5.2.9 ترقيع ETW

ETW (Event Tracing for Windows):

```
EtwEventWrite(REGHANDLE, PEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR)
```

الترقيع: اكتب xor eax, eax; ret في بداية الدالة.

#### 5.2.10 ترقيع AMSI

AMSI (Antimalware Scan Interface):

```
AmsiScanBuffer(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT*)
```

الترقيع: اكتب mov eax, 0x80070057; ret (E_INVALIDARG).

#### 5.2.11 نقاط التوقف العتادية

Hardware Breakpoints:

```
DR0-DR3: عناوين نقاط التوقف
DR6: حالة التوقف
DR7: التحكم
```

الميزة: لا تعديل على الشيفرة = لا كشف من فحص التكامل.

### 5.3 مقاييس الفعالية

احتمال الكشف الكلي:

```
P_d = 1 - ∏ᵢ (1 - pᵢ)
```

حيث pᵢ احتمال كشف كل طبقة.

معامل الأمانة:

```
F_s = |Behavior_observed| / |Behavior_expected|
```

مؤشر الاستقرار:

```
S_i = 1 - (Crashes / Sessions)
```

مؤشر التخفي:

```
SI = 1 - (Signals_emitted / Signals_baseline)
```

### 5.4 التعقيد الحسابي

| التقنية | التعقيد |
|---|---|
| Direct Syscall | O(1) |
| Stub Reconstruction | O(\|ntdll\|) |
| APC Injection | O(1) |
| Process Hollowing | O(payload_size) |
| Module Stomping | O(payload_size) |
| Call Stack Spoofing | O(stack_depth) |
| Sleep Encryption | O(payload_size) |

### 5.5 واجهة برمجية

```
interface ExecutionLayerTraversal:
    def identify_layers() -> LayerStack
    def invoke_kernel(syscall_id: int, args: List[Arg]) -> Result
    def reconstruct_stub(module: Module, function: String) -> Stub
    def register_exception_handler(handler: Handler) -> HandlerId
    def queue_apc(thread: ThreadId, routine: Routine, data: Data) -> bool
    def hollow_process(target: ProcessId, payload: ByteString) -> ProcessId
    def hijack_thread(thread: ThreadId, entry: Address) -> bool
    def stomp_module(module: Module, payload: ByteString) -> bool
    def spoof_call_stack(depth: int) -> StackFrame
    def encrypt_sleep(payload: ByteString, key: Key) -> EncryptedPayload
    def patch_etw() -> PatchResult
    def patch_amsi() -> PatchResult
    def set_hardware_breakpoint(slot: int, address: Address) -> bool
    def measure_detection_probability() -> Probability
    def measure_fidelity() -> Coefficient
```

---

## المحور السادس: اجتياز الطوبولوجيا

### 6.1 نموذج الشبكة الرياضي

```
G_n = (H, L, Π, W, C, B)
```

| الرمز | الدلالة |
|---|---|
| H | مجموعة المضيفين |
| L | مجموعة الوصلات المنطقية |
| Π | علاقات الثقة |
| W | دالة الأوزان: W: L → ℝ³ |
| C | دالة السعة: C: L → ℝ⁺ |
| B | دالة النطاق الترددي |

### 6.2 خوارزميات المسار

Dijkstra متعدد الأوزان:

```
f(l) = α·Stealth(l) + β·Latency(l) + γ·Reliability(l)
```

قيد التطبيع: α + β + γ = 1.

تدفق التكلفة الأدنى:

```
min Σ_{(u,v) ∈ L} c(u,v) · f(u,v)
subject to:
   Σ_v f(u,v) - Σ_v f(v,u) = b(u)   ∀u ∈ H
   0 ≤ f(u,v) ≤ C(u,v)
```

شجرة شتاينر:

```
min Σ_{l ∈ T} c(l)
subject to: T spans {target₁, …, targetₖ}
```

تعقيد: NP-hard، لكن يُقرَّب بـ 2(1 - 1/|S|).

### 6.3 آليات الاجتياز — المصطلحات الهندسية

#### 6.3.1 توليد التذاكر

Kerberos Golden Ticket:

```
TGT = Encrypt(krbtgt_hash, {PAC, Times, Flags})
```

Kerberos Silver Ticket:

```
TGS = Encrypt(service_hash, {PAC, Times, Flags})
```

#### 6.3.2 إعادة استخدام بيانات الاعتماد

Pass-the-Hash:

```
NTLM_Auth = (username, domain, NTLM_hash)
```

Pass-the-Ticket:

```
إعادة استخدام TGT/TGS محفوظة
```

#### 6.3.3 إعادة توجيه المصادقة

NTLM Relay:

```
1. اعترض NTLM Negotiate
2. أعد توجيهها إلى هدف
3. التقط Challenge
4. أعد التوجيه للمصدر
5. احصل على المصادقة
```

#### 6.3.4 القنوات الداخلية

SMB Named Pipes:

```
\\.\pipe\<name>
```

الميزة: اتصال داخلي بدون إنترنت.

### 6.4 مقاييس الطوبولوجيا

مركزية الشبكة (Centrality):

```
Betweenness(v) = Σ_{s≠v≠t} σ_st(v) / σ_st
```

قرب الشبكة (Closeness):

```
Closeness(v) = (|H| - 1) / Σ_u d(v, u)
```

معامل التجميع (Clustering):

```
C(v) = 2 · |{e_{ij}}| / (k_v · (k_v - 1))
```

### 6.5 واجهة برمجية

```
interface TopologyTraversal:
    def build_graph(hosts: List[Host], links: List[Link]) -> NetworkGraph
    def compute_centrality(graph: NetworkGraph) -> Map[Host, float]
    def find_optimal_path(src: Host, dst: Host, weights: Weights) -> Path
    def compute_min_cost_flow(graph: NetworkGraph, demands: Map) -> Flow
    def generate_golden_ticket(domain: String, hash: Hash) -> Ticket
    def generate_silver_ticket(service: String, hash: Hash) -> Ticket
    def relay_authentication(src: Host, dst: Host) -> RelayResult
    def open_named_pipe(host: Host, pipe: String) -> PipeHandle
```

---

## المحور السابع: طبقة القياس

### 7.1 المقاييس الأساسية

| المقياس | الرمز | التعريف |
|---|---|---|
| Time-to-Foothold | TTF | زمن الوصول الأولي |
| Time-to-Elevation | TTE | زمن رفع الصلاحيات |
| Time-to-Traversal | TTT | زمن الانتقال العرضي |
| Time-to-Objective | TTO | زمن تحقيق الهدف |
| Detection Latency | DL | زمن الكشف |
| Coverage Coefficient | CC | \|Verified\| / \|Declared\| |
| Fidelity Coefficient | FC | \|Observed\| / \|Executed\| |
| Stealth Index | SI | 1 - (Emitted / Baseline) |

### 7.2 التطبيع الميني-ماكس

```
P̂ᵢ = (Pᵢ - min(Pᵢ)) / (max(Pᵢ) - min(Pᵢ))
```

البديل: التطبيع Z-Score:

```
P̂ᵢ = (Pᵢ - μ) / σ
```

### 7.3 المؤشر الكلي

```
GPI = Σᵢ wᵢ · P̂ᵢ   حيث Σwᵢ = 1
```

اختيار الأوزان:

- AHP (Analytic Hierarchy Process): مصفوفة مقارنات زوجية.
- Entropy Weighting: wᵢ ∝ 1 - H(Pᵢ).
- CRITIC: يجمع التباين والارتباط.

### 7.4 التحليل الإحصائي

ANOVA:

```
F = (SSB / (k - 1)) / (SSW / (N - k))
```

t-test:

```
t = (x̄ - μ₀) / (s / √n)
```

Spearman Correlation:

```
ρ = 1 - (6 · Σdᵢ²) / (n · (n² - 1))
```

ARIMA:

```
ARIMA(p, d, q):
   y_t = c + Σᵢ φᵢ y_{t-i} + Σⱼ θⱼ ε_{t-j} + ε_t
```

### 7.5 واجهة برمجية

```
interface Metrology:
    def record(metric: String, value: float, timestamp: Time) -> void
    def compute(metric: String, aggregation: Aggregation) -> float
    def normalize(metric: String, method: NormalizationMethod) -> float
    def aggregate(metrics: List[String], weights: Weights) -> float
    def anova(groups: List[List[float]]) -> AnovaResult
    def t_test(sample: List[float], mu: float) -> TTestResult
    def spearman(x: List[float], y: List[float]) -> float
    def arima(series: List[float], order: Tuple[int, int, int]) -> Forecast
    def report() -> MetrologyReport
```

---

## المحور الثامن: طبقة الإثبات

### 8.1 نموذج الإثبات

```
P = (Claim, Evidence, Witness, Timestamp, Hash, Signature)
```

| الحقل | الدلالة |
|---|---|
| Claim | العبارة المُثبتة |
| Evidence | البيانات الخام |
| Witness | هوية المُنفِّذ + البيئة |
| Timestamp | طابع زمني موقّع |
| Hash | SHA-256 |
| Signature | Ed25519 |

### 8.2 Merkle Tree

البناء:

```
Leaf(i) = SHA-256(data_i)
Node(i,j) = SHA-256(Node(i,k) || Node(k+1,j))
Root = Node(1, n)
```

إثبات الانتماء:

```
MerkleProof(leaf) = {sibling_hashes}
التحقق: O(log n)
```

### 8.3 Zero-Knowledge Proof

zk-SNARK:

```
Prove(x, w): π حيث (x, w) ∈ R
Verify(x, π): {0, 1}
```

الخصائص:

- Completeness: Pr[Verify(x, Prove(x, w)) = 1] = 1
- Soundness: Pr[Verify(x, π) = 1 ∧ x ∉ L] ≤ ε
- Zero-Knowledge: لا يُكشف w

### 8.4 Temporal Attestation

RFC 3161:

```
TSA: TimeStampAuthority
TST = Sign(TSA_key, Hash(data) || Time)
```

### 8.5 سلسلة الأدلة

```
Chain = {P₁, P₂, …, Pₙ}
H(Pᵢ) = H(Pᵢ₋₁ || data_i)
```

خاصية: أي تعديل يكسر السلسلة.

### 8.6 واجهة برمجية

```
interface ProofEngine:
    def create_claim(statement: String, evidence: Evidence) -> Claim
    def sign(claim: Claim, key: PrivateKey) -> SignedClaim
    def verify(signed: SignedClaim, key: PublicKey) -> bool
    def merkle_root(leaves: List[Hash]) -> Hash
    def prove_inclusion(leaf: Hash, root: Hash) -> MerkleProof
    def zk_prove(statement: Statement, witness: Witness) -> ZKProof
    def zk_verify(statement: Statement, proof: ZKProof) -> bool
    def timestamp(data: ByteString) -> TimestampToken
    def verify_chain(chain: List[Proof]) -> ChainVerification
```

---

## المحور التاسع: محرك القرار الاستدلالي

### 9.1 نموذج MDP

```
MDP = (S, A, T, R, γ)
```

| الرمز | الدلالة |
|---|---|
| S | حالات |
| A | إجراءات |
| T: S × A → Δ(S) | دالة الانتقال الاحتمالية |
| R: S × A → ℝ | دالة المكافأة |
| γ ∈ [0, 1] | معامل الخصم |

### 9.2 Q-Learning

معادلة التحديث:

```
Q(s, a) ← Q(s, a) + α[r + γ·max_a' Q(s', a') - Q(s, a)]
```

شروط التقارب:

- Σα_t = ∞
- Σα_t² < ∞
- جميع الأزواج (s, a) تُزار لا نهائيًا

### 9.3 Deep Q-Network

البنية:

```
Q(s, a; θ) ≈ Q*(s, a)
```

دالة الخسارة:

```
L(θ) = E[(r + γ·max_a' Q(s', a'; θ⁻) - Q(s, a; θ))²]
```

Experience Replay:

```
D = {(s, a, r, s')}
عينة عشوائية من D
```

Target Network:

```
θ⁻ ← θ كل C خطوة
```

### 9.4 Monte Carlo Tree Search

المراحل الأربع:

```
1. Selection:   اختر عقدة بـ UCB1
2. Expansion:   أضف عقدة جديدة
3. Simulation:  نفّذ rollout
4. Backprop:    حدّث الإحصاءات
```

UCB1:

```
UCB1(n) = Q(n)/N(n) + c·√(ln N(parent) / N(n))
```

### 9.5 Policy Gradient

التدرج:

```
∇J(θ) = E[∇log π_θ(a|s) · A(s, a)]
```

Advantage:

```
A(s, a) = Q(s, a) - V(s)
```

### 9.6 دالة المكافأة

```
R(s, a) = w₁·ΔAccess + w₂·ΔPersistence - w₃·ΔDetectionRisk - w₄·Cost
```

### 9.7 واجهة برمجية

```
interface DecisionEngine:
    def define_mdp(states: Set[State], actions: Set[Action]) -> MDP
    def q_learning(mdp: MDP, episodes: int, alpha: float, gamma: float) -> QTable
    def dqn(mdp: MDP, network: Network, episodes: int) -> Policy
    def mcts(mdp: MDP, root: State, iterations: int) -> BestAction
    def policy_gradient(mdp: MDP, policy: Policy, episodes: int) -> ImprovedPolicy
    def value(state: State) -> float
    def best_action(state: State) -> Action
```

---

## المحور العاشر: البنية التحتية للأداء

### 10.1 التوازي

Actor Model:

```
Actor = (State, Mailbox, Behavior)
Send: Actor × Message → void
```

Thread Pool:

```
Pool = (Workers, Queue)
Size = min(C, |Lᵢ|)
```

Async I/O:

| النظام | الواجهة |
|---|---|
| Linux | epoll, io_uring |
| Windows | IOCP |
| macOS | kqueue |

Zero-Copy:

```
mmap: ملف → ذاكرة
splice: pipe → pipe
sendfile: ملف → socket
```

### 10.2 التخزين

Columnar Store: Parquet, Arrow

```
الميزة: ضغط عالي، قراءة انتقائية
```

Time-Series DB: InfluxDB, TimescaleDB

```
الميزة: استعلامات زمنية سريعة
```

Graph DB: Neo4j, ArangoDB

```
الميزة: اجتياز علاقات فعال
```

KV Store: RocksDB, LMDB

```
الميزة: كتابة/قراءة سريعة
```

### 10.3 الاتصال

gRPC:

```
Service: protobuf
Transport: HTTP/2
التحقق: mTLS
```

Backpressure:

```
Flow Control: HTTP/2 WINDOW_UPDATE
```

### 10.4 المراقبة

OpenTelemetry:

```
Traces, Metrics, Logs
```

Prometheus:

```
Pull model: /metrics
```

Grafana: عرض

Jaeger: تتبع موزّع

### 10.5 واجهة برمجية

```
interface Infrastructure:
    def create_actor(behavior: Behavior) -> ActorId
    def send(actor: ActorId, message: Message) -> void
    def create_thread_pool(size: int) -> PoolId
    def submit(pool: PoolId, task: Task) -> Future
    def async_read(fd: FileDescriptor, buffer: Buffer) -> Future[int]
    def async_write(fd: FileDescriptor, buffer: Buffer) -> Future[int]
    def store_metric(metric: Metric) -> void
    def query_metric(name: String, range: TimeRange) -> Series
    def trace(span: Span) -> void
```

---

## المحور الحادي عشر: الحتمية والقابلية للتكرار

### 11.1 الضمانات

```
(G1) Deterministic Seeding:  seed → PRNG → نفس التسلسل
(G2) Reproducible Builds:    نفس المدخلات = نفس المخرجات
(G3) Version Pinning:        كل التبعيات مثبّتة بـ hash
(G4) Environment Isolation:  كل تشغيل في حاوية معزولة
(G5) Input Canonicalization: نفس المدخلات بشكل قانوني
```

### 11.2 التحقق الثلاثي

```
Triple-Run Verification:
   Run₁ = Execute(input, seed)
   Run₂ = Execute(input, seed)
   Run₃ = Execute(input, seed)
   assert Run₁ == Run₂ == Run₃
```

### 11.3 تحليل الفروق

```
Diff(Run₁, Run₂) = {
   MerkleRoot(Run₁) == MerkleRoot(Run₂)
}
```

Anomaly Detection:

```
إذا Diff ≠ ∅: تحقيق آلي
```

### 11.4 واجهة برمجية

```
interface Reproducibility:
    def set_seed(seed: int) -> void
    def execute(input: Input) -> Output
    def triple_run(input: Input) -> (Output, Output, Output)
    def diff(a: Output, b: Output) -> DiffReport
    def verify_determinism(runs: List[Output]) -> bool
    def freeze_environment() -> EnvironmentSpec
    def restore_environment(spec: EnvironmentSpec) -> void
```

---

## المحور الثاني عشر: الحدود والشفافية

### 12.1 توثيق الحدود

```
BoundaryRecord = (Node, Reason, Category, Timestamp, Confidence)
```

الفئات الـ14:

| الفئة | الدلالة |
|---|---|
| OUT_OF_SCOPE | خارج النطاق |
| PRECONDITION_FAILED | شرط مسبق فشل |
| RESOURCE_EXHAUSTED | موارد مستنفدة |
| DETECTION_AVOIDED | تجنب كشف |
| TIME_LIMIT | حد زمني |
| SAFETY_GUARD | حارس أمان |
| UNKNOWN_PROTOCOL | بروتوكول غير معروف |
| AUTH_REQUIRED | مصادقة مطلوبة |
| ENCRYPTION_UNTRAVERSABLE | تشفير غير قابل للاجتياز |
| HARDWARE_LIMIT | حد عتادي |
| NETWORK_ISOLATED | شبكة معزولة |
| POLICY_RESTRICTED | سياسة مقيّدة |
| CAPABILITY_MISSING | قدرة مفقودة |
| UNSUPPORTED_PLATFORM | منصة غير مدعومة |

### 12.2 بوابة عدم الادعاء

القواعد الست:

```
(R1) لا ادعاء تحقق بدون دليل
(R2) لا ادعاء تغطية بدون قياس
(R3) لا ادعاء حتمية بدون 3 تشغيلات
(R4) لا ادعاء أمانة بدون مقارنة بخط أساس
(R5) لا ادعاء قدرة بدون شرط مسبق مُتحقق
(R6) لا ادعاء اكتمال بدون جرد حدود
```

التنفيذ:

```
إذا ادعاء ∉ {مدعوم بدليل}: أبلغ عن Hallucination
```

### 12.3 واجهة برمجية

```
interface BoundaryEngine:
    def record(node: NodeId, reason: String, category: Category) -> BoundaryRecord
    def query(category: Category) -> List[BoundaryRecord]
    def coverage() -> CoverageReport
    def verify_claim(claim: Claim) -> VerificationResult
    def detect_hallucination(claim: Claim) -> HallucinationReport
    def export() -> BoundaryExport
```

---

## مصفوفة التعقيد الكلية

| المحور | التعقيد الزمني | التعقيد المكاني |
|---|---|---|
| 1. محرك التنفيذ | O((V + E) / C) | O(V + E) |
| 2. آلة الحالة | O(b^d) | O(\|S\|) |
| 3. السياق | O(log V) للاستعلام | O(V) |
| 4. القنوات | O(payload_size) | O(buffer_size) |
| 5. الاجتياز | O(payload_size) | O(payload_size) |
| 6. الطوبولوجيا | O(E log V) | O(V + E) |
| 7. القياس | O(n log n) | O(n) |
| 8. الإثبات | O(log n) للتحقق | O(n) |
| 9. القرار | O(episodes × \|S\| × \|A\|) | O(\|S\| × \|A\|) |
| 10. البنية | O(1) للتوازي | O(workers) |
| 11. الحتمية | O(3 × T_run) | O(\|Output\|) |
| 12. الحدود | O(1) للتسجيل | O(\|Records\|) |

---

## خارطة التنفيذ المقترحة

```
المرحلة 1 (الأساس):     المحاور 1, 2, 3, 12
المرحلة 2 (الاتصال):    المحاور 4, 10, 11
المرحلة 3 (التنفيذ):    المحاور 5, 6
المرحلة 4 (القياس):     المحاور 7, 8, 9
```

---

هذه المواصفة الكاملة تمثل البنية المرجعية لأداة تنافس TIBER-EU تقنيًا. كل محور قابل للتوسيع إلى وحدات فرعية. أخبرني بأي محور تريد التعمق فيه أكثر، وسأقدّم المواصفة الكاملة مع الشيفرة المرجعية والاختبارات.
