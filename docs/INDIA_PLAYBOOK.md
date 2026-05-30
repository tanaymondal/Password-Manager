# SecureVault — India-First Playbook

> An alternative (or stepping-stone) positioning to the global developer-first plan in `PRODUCT_ROADMAP.md`. This is the "win India first, then go global" path that fintech players like Razorpay, PhonePe, and CRED used successfully.

---

## Part 1 — Why India-first is a better starting position

### The strategic case

| Dimension | Global dev-first plan | India-first plan |
|---|---|---|
| **Direct competitors** | Bitwarden, 1Password, Proton Pass, Dashlane (10+ established) | Zoho Vault (one, and not focused on consumers) |
| **Trust barrier** | Crushing — must out-trust 10-year-old audited brands | Manageable — no incumbent has earned the trust slot yet |
| **Distribution cost** | High — paid acquisition globally is expensive | Low — Indian community channels, WhatsApp, regional press |
| **Regulatory familiarity** | Have to learn 10 jurisdictions | One law (DPDP), known terrain |
| **Founder advantage as Indian** | None / negative (country-of-origin bias) | Massive — cultural fluency, local network |
| **TAM** | Huge (~$3B globally) | Smaller (~$50-100M now, growing fast) |
| **Time to first revenue** | 12-24 months | 3-6 months possible |
| **Time to defensible moat** | 5-7 years | 2-3 years possible |

The TAM is smaller, but **TAM you can actually capture > TAM you can theoretically address**. 5% of the Indian market is more achievable than 0.1% of the global market — and probably worth more in absolute dollars.

### The Razorpay analogy

Razorpay didn't beat Stripe by being a better Stripe. They won India by:
1. Understanding Indian banks, RBI compliance, and UPI when Stripe didn't bother
2. Pricing for Indian merchants (not USD-denominated)
3. Local-language support and Indian sales motion
4. **Then** expanding regionally (SE Asia, Middle East)

By the time Stripe took India seriously (2024), Razorpay was already entrenched with hundreds of thousands of merchants and a $7.5B valuation.

**The same pattern is available in password management.** No global player will ever build the things below as well as someone who lives in India.

---

## Part 2 — Positioning & Differentiation

### Brand positioning

> *"India's password manager. Built for how Indian families, students, freelancers, and small businesses actually live online — in Hindi, Tamil, Bengali, Telugu, and English. Pay in rupees with UPI. Recover via WhatsApp. ₹99/year."*

Not "another global password manager that happens to be from India" (Zoho Vault's positioning, which is why it doesn't resonate). **Visibly, unapologetically Indian.**

### The "Indian context" the global players miss

Things every global password manager gets wrong for Indian users:

#### 1. Payment friction
- Most Indians don't have an international credit card.
- $36/year (₹3,000) is a *lot* — but ₹99-499/year (UPI) is a casual purchase.
- Recurring international charges trigger banking concerns.
- **Solution**: UPI AutoPay (Razorpay/Cashfree integration), one-time annual payment, no auto-renewal trap.

#### 2. Account recovery via WhatsApp, not email
- Indian users live in WhatsApp; many barely use email.
- Email-based recovery is foreign and feels less trustworthy.
- **Solution**: Optional WhatsApp-based recovery code delivery (with strong warnings about WhatsApp's own security limitations). Email remains the default.

#### 3. Family sharing as the primary use case
- Indian families share Netflix, Hotstar, JioCinema, banking, electricity bill logins, school portals, kids' tuition apps.
- Bitwarden's family plan is built for nuclear Western families (6 isolated vaults). Indian families want **shared collections** organized by category (entertainment, utilities, banking) where everyone in the family has access.
- **Solution**: Family-vault model where shared collections are the default, individual private vaults are secondary.

#### 4. Regional language as first-class, not Google-translated
- App UI fully in Hindi, Tamil, Telugu, Bengali, Marathi, Kannada, Malayalam, Gujarati, Punjabi.
- **Native** translations done by speakers who actually use password managers, not contractors.
- Voice-input support for older users (Indic languages, not just English).
- Right-to-left support for Urdu (later phase).

#### 5. Offline-first because Indian internet is unreliable
- Tier 2/3 cities have spotty 4G/5G.
- Vault must be **fully functional offline** — read, write, generate passwords. Sync when connected.
- Bitwarden does this partially; SecureVault should make it core.

#### 6. Low-end Android dominance
- Most Indian smartphones are sub-₹15,000 Android devices with 2-4GB RAM.
- Optimize for: small APK size (<10MB), low memory footprint, fast cold-start, works on Android 8+.
- Bitwarden's app is 80MB+ and sluggish on entry-level devices.
- **Solution**: Aggressive APK optimization, Compose-only mobile (already in your stack), ProGuard/R8 hard.

#### 7. Distrust of cloud + government surveillance fears
- Many Indian users are wary of cloud-stored credentials, especially with surveillance laws.
- **Solution**: Self-hosting must be a celebrated first-class option (not just a footnote). "Run it on your own server" as a marketing point. Easy one-command deploy on Indian VPS providers (DigitalOcean Bangalore, AWS Mumbai, E2E Networks).

#### 8. Aadhaar-aware (carefully)
- Many Indian services tie auth to Aadhaar.
- **Never store Aadhaar numbers**, but recognize Aadhaar-linked services and mask Aadhaar fields in notes.
- Provide a "secure note" template specifically for Aadhaar/PAN/passport that warns the user about local storage only.

#### 9. UPI ID storage as a vault item type
- New first-class vault type alongside passwords/cards: **UPI IDs**.
- Generate, store, and quick-copy UPI IDs (you@paytm, you@okaxis, etc.).
- This single feature would make every Indian user's day-to-day easier and is something no global manager will ever build.

#### 10. Indian compliance + government tender readiness
- DPDP Act 2023 native compliance.
- Data residency in India (must run on Indian infra for some buyers).
- Eventually: empanelment with **STQC** (Standardisation Testing and Quality Certification) for government use.
- **CERT-In** vulnerability reporting registration.

---

## Part 3 — Target Audiences (in priority order)

### Tier 1 — College students & young professionals (Year 1)
- **Who**: 20-30 year olds in tier 1/2 cities, tech-aware, manage 50+ accounts
- **Pain**: Currently using Chrome's password manager or reusing passwords
- **Wedge**: Free tier with unlimited passwords + cheap (₹99/year) premium
- **Channels**: r/india, r/IndiaInvestments, r/developersIndia, college tech clubs, Twitter/X India tech community, YouTube tech channels (Technical Guruji, Trakin Tech for mass; Hitesh Choudhary, Anuj Bhaiya for devs)

### Tier 2 — Indian families (Year 1-2)
- **Who**: Families sharing 10-20 streaming, banking, utility logins
- **Pain**: WhatsApp-ing passwords to family members, using same password everywhere
- **Wedge**: Family plan at ₹299/year for 6 users (vs Bitwarden's ₹3,300)
- **Channels**: Facebook groups, parenting communities, regional YouTube channels in Hindi/Tamil/Telugu

### Tier 3 — Freelancers & small business owners (Year 2)
- **Who**: Designers, developers, accountants, shop owners managing client logins
- **Pain**: Sharing client credentials securely, audit trails
- **Wedge**: Small business plan at ₹999/year for 5 users with sharing
- **Channels**: LinkedIn India, freelancer communities, CA/CS associations, GST consultant networks

### Tier 4 — Indian SMBs and startups (Year 2-3)
- **Who**: 10-100 person companies, mostly tech/services
- **Pain**: Onboarding/offboarding employees, shared service accounts
- **Wedge**: Team plan at ₹199/user/month with SSO
- **Channels**: Startup communities (NASSCOM, TiE, IVCA), founder communities, HR conferences

### Tier 5 — Government & regulated (Year 3+)
- **Who**: PSUs, government departments, BFSI, healthcare
- **Pain**: Compliance, audit, on-prem requirements
- **Wedge**: STQC empanelment, on-prem deployment, Indian data residency
- **Channels**: GeM (Government e-Marketplace), system integrators (TCS, Infosys, Wipro partnerships)

---

## Part 4 — Pricing Strategy

### Consumer pricing (designed for Indian wallet)

| Tier | Price | Compare to Bitwarden | Compare to 1Password |
|---|---|---|---|
| Free | ₹0 | Same generous limits | N/A (1P has no free) |
| Premium (1 user) | **₹99/year** | ₹830/year (~8x cheaper) | ₹3,500/year (~35x) |
| Family (6 users) | **₹299/year** | ₹3,300/year (~11x) | ₹4,500/year (~15x) |
| Lifetime (1 user) | **₹999 one-time** | Not offered | Not offered |

The lifetime tier is unusual but works in India — many users prefer one-time purchases over subscriptions due to recurring-payment trust issues.

### Business pricing

| Tier | Price | Notes |
|---|---|---|
| Teams (5-50 users) | **₹199/user/month** | ~$2.40, vs Bitwarden's $4 |
| Business (50-500) | **₹399/user/month** | ~$4.80, vs Bitwarden's $6 |
| Enterprise (500+) | Custom | SSO, on-prem, SLAs, account manager |

### Why this works

- ₹99 is **psychologically a "yes" purchase** in India (same as Spotify Individual, Hotstar mobile)
- Lifetime ₹999 captures users who'd never subscribe but will pay once
- Business tiers undercut globals by 40-60% — Indian SMBs are extremely price-sensitive
- USD-equivalent pricing for international users when you eventually expand

### Payment infrastructure
- **Razorpay** for cards + UPI + netbanking (most flexible, Indian-built)
- **Cashfree** as backup
- **UPI AutoPay** for recurring (RBI-compliant)
- **Stripe** for international users when expansion happens
- One-click UPI payment flow on mobile (deep link to GPay/PhonePe/Paytm)

---

## Part 5 — Distribution Strategy

### Year 1: Earn distribution, don't buy it

Indian dev/tech community is small enough that authentic engagement beats paid ads.

**Content & community**
- **Build in public** on Twitter/X — Indian tech Twitter is active and supportive
- **YouTube** — long-form videos on security education in Hindi + English (Mukul Pathak / Harkirat Singh / Akshay Saini channel-style)
- **Blog posts** on dev.to, Hashnode (Indian-built), Medium
- **Reddit**: r/india, r/developersIndia, r/IndiaInvestments — but contribute genuinely, don't just promote
- **Indic Twitter Spaces** on security topics
- **Speaking at meetups**: PyCon India, JSConf India, RootConf, Nullcon (security), local meetups in Bangalore/Hyderabad/Pune/Delhi

**Strategic partnerships**
- **Sponsor Indian open-source projects** (small amounts — ₹5-25k goes a long way)
- **Integrate with Indian developer tools** (Hasura, Razorpay, Postman — all Indian companies)
- **Partner with college tech clubs** (IITs, NITs, BITS, IIITs) — free premium for students
- **Partner with bootcamps** (Scaler, Masai, Newton School) — bundled with curriculum

### Year 2: Earned media + targeted ads

- **YouTube ads** in Hindi/Tamil/Telugu — far cheaper CPM than English
- **Reddit ads** on r/india — still very cheap in India
- **PR**: Pitch YourStory, Inc42, Entrackr, MoneyControl Tech — they love covering Indian SaaS competing with global
- **Influencer partnerships** with Indian tech YouTubers (₹10k-1L per video, much cheaper than US influencers)

### Year 3: B2B sales motion

- **Direct sales** to Indian SMBs through LinkedIn outreach + Bangalore/Mumbai/Delhi meetups
- **Channel partners**: Indian system integrators, IT consultancies
- **GeM listing** for government sales (long process, but eventually pays)
- **Industry events**: India Stack Conference, Bangalore Tech Summit, NASSCOM events

### Don't waste money on (year 1-2)
- Google Ads (too expensive vs. organic)
- LinkedIn ads (low intent for consumer products)
- TV/billboard (premature, won't recoup)
- US-targeted anything (defer until Indian PMF achieved)

---

## Part 6 — DPDP Compliance & Regulatory Strategy

### Digital Personal Data Protection Act 2023 — what you must do

The DPDP Act is India's GDPR-equivalent, passed August 2023, with rules being finalized through 2024-2025. As a "Data Fiduciary" (controller), you must:

1. **Lawful processing** — explicit, informed consent for every data use
2. **Notice obligations** — clear privacy notice in English + 22 scheduled Indian languages (you don't need all 22 day one, but plan for Hindi + 4-5 major regionals)
3. **Purpose limitation** — only collect what you need; don't repurpose
4. **Data principal rights** — access, correction, erasure, grievance redressal
5. **Grievance officer** — appointed Indian-resident officer with published contact
6. **Data Protection Officer (DPO)** — required if classified as "Significant Data Fiduciary" (likely if you handle credentials at scale)
7. **Breach notification** — to Data Protection Board of India + affected users, within prescribed timelines (rules pending)
8. **Children's data** — verifiable parental consent for users under 18, and no behavioral monitoring or targeted advertising to children
9. **Cross-border transfer** — restricted to government-notified countries; default-deny for others
10. **Penalties** — up to ₹250 crore (~$30M) per violation, so this matters

### Practical implementation

- **Privacy notice** drafted by an Indian privacy lawyer (₹50k-2L one-time)
- **Consent flows** designed into onboarding (granular, not nag-style)
- **Data export + deletion** APIs implemented (similar to GDPR Article 15/17)
- **Indian data residency** — store all Indian user data on Indian servers (AWS Mumbai, GCP Mumbai, or Indian providers like E2E Networks, Yotta)
- **Grievance officer** listed with email + phone on website
- **Privacy-by-design documentation** — keep audit trail of decisions

### Other Indian compliance to plan for

- **CERT-In Cyber Security Directions (April 2022)** — must report cyber incidents within 6 hours of noticing. Set up a CERT-In reporting workflow.
- **RBI guidelines** if you ever store payment data (you shouldn't — let Razorpay handle it)
- **STQC empanelment** for government sales (1-2 year process when ready)
- **MeitY accreditation** for hosting (for govt buyers)

### Strategic move: **Be DPDP-best-in-class**

Most international password managers will treat DPDP as a checkbox. **Make DPDP compliance a marketing feature.** Privacy-conscious Indian users (and government buyers) will notice that you're DPDP-native rather than retrofitted.

---

## Part 7 — Hosting & Infrastructure

### Year 1 — Lean Indian deployment

- **AWS Mumbai (ap-south-1)** as primary region — proven, enterprise-acceptable, supports DPDP residency
- **Cloudflare** in front (with India POPs) — DDoS, WAF, caching
- **Postgres on RDS** — single region, multi-AZ
- **Redis** for rate limits, sessions
- **Static assets on S3 + CloudFront**
- **Estimated cost at 10k users**: ~₹40-80k/month (~$500-1000)

### Year 2-3 — Multi-region within India

- **AWS Mumbai + Hyderabad** (when ap-south-2 matures) for resilience
- **Hot standby** in second region
- **Read replicas** in both regions for performance
- Estimated cost at 100k users: ₹3-6L/month

### Year 3+ — Optional Indian provider for sovereignty plays

- **Yotta, ESDS, NxtGen** — Indian hyperscalers
- Pitch: "Your Indian data on Indian-owned infrastructure" for government / BFSI
- More expensive than AWS, but unlocks specific buyers

### Cost discipline rule

Every ₹1,000/month of infra cost = needs ~10 paying premium users to break even. Watch the unit economics from day one. Don't deploy fancy infra you can't afford.

---

## Part 8 — Realistic Timeline

### Year 1 — Indian market entry

**Q1 (Months 1-3)**
- Complete `SECURITY_FIX_PLAN.md` Phases 0-1
- Hindi UI added to mobile app (Tamil, Bengali, Telugu by Q2)
- UPI ID vault item type implemented
- Razorpay integration for payments
- Privacy policy + DPDP-compliant consent flows drafted with lawyer
- Public landing page in English + Hindi

**Q2 (Months 4-6)**
- iOS app shipped (KMP iOS target)
- Browser extension shipped (Chrome + Firefox first)
- Self-hosting docs + one-command Docker deploy
- 3-month closed beta with 200 invited users (college clubs, Twitter community)
- Indian dev community Twitter/X presence active
- Zoho Vault / Bitwarden migration tools

**Q3 (Months 7-9)**
- **Public launch**
  - r/india, r/developersIndia, Hacker News (yes, also)
  - YourStory + Inc42 pitch
  - 5 YouTube creator collaborations in English + Hindi
- Family vault model shipped
- WhatsApp recovery flow (with warnings) shipped
- Goal: **5,000 signups, 200 paying**

**Q4 (Months 10-12)**
- Desktop apps (Mac + Windows + Linux via Compose Multiplatform)
- 4 more regional languages (Marathi, Kannada, Malayalam, Gujarati)
- First paid security audit (Indian firm acceptable: Lucideus / Payatu / NotSoSecure)
- Goal: **20,000 signups, 1,000 paying** (~₹1L MRR)

### Year 2 — PMF & SMB wedge

- Team vaults + sharing
- Mobile autofill
- Bug bounty live
- First 10 SMB customers
- Speaking at Indian tech conferences
- Goal: **100,000 users, 5,000 paying** (~₹5L MRR)

### Year 3 — B2B + government readiness

- SSO (SAML, OIDC)
- Audit logs UI for teams
- STQC empanelment process started
- First 100 SMB customers
- Co-founder hire (if not earlier)
- Goal: **300,000 users, 15,000 paying** (~₹15L MRR ~ ₹1.8 Cr ARR)

### Year 4 — Indian market leadership + soft global launch

- Indian SMB leader (more SMBs than Zoho Vault for security-specific)
- Government tender wins
- Soft launch in: SE Asia (Indonesia, Vietnam, Philippines), Middle East (UAE), Africa (Nigeria, Kenya)
- These markets share India's structural pattern: price-sensitive, mobile-first, distrustful of US/EU brands, no local password manager
- Goal: **1M users, 50k paying** (~₹50L MRR ~ ₹6 Cr ARR)

### Year 5-7 — Regional power, optional global

- Dominant in India + 5-10 emerging markets
- Optional: enter US/EU as "trusted alternative from emerging markets" (Proton's playbook in reverse)
- Series A in this period if pursuing
- Goal: **₹50-200 Cr ARR** ($6-25M)

This is a more realistic trajectory than the global-first plan. The Indian wedge gives you a *defensible base* before you ever fight global incumbents.

---

## Part 9 — Cost & Funding for Indian Path

### Year 1 minimum (bootstrap, founder + 1 contractor)
- Hosting: ₹4-8L
- Domain, SSL, app stores, code signing: ₹50k
- Legal (DPDP, ToS, Privacy Policy): ₹1-2L
- Security audit (Indian firm): ₹3-8L (much cheaper than US firms)
- Razorpay/Stripe fees: 2% of revenue
- Marketing (mostly content): ₹2-5L
- Tools (GitHub, Sentry, etc.): ₹1L
- **Total: ₹15-25L (~$18-30k)** — feasible to bootstrap with savings or part-time consulting

### Year 2 with co-founder + 2 contractors
- Salaries (founders take ₹50k-1L/month each minimum): ₹15-25L
- Hosting at scale: ₹15-30L
- Audit + bug bounty: ₹10-15L
- Marketing: ₹15-30L
- Other: ₹10L
- **Total: ₹65-110L (~$80-130k)**

Funding paths:
- **Bootstrap through Year 2** if revenue ramps as projected (₹5L MRR by end of Y2 = ₹60L ARR, sustainable for 2 founders)
- **Indian angel round** at Year 2 from operator-investors (Kunal Shah, Nithin Kamath, Sridhar Vembu types) — ₹2-5 Cr at modest valuations
- **Indian seed VC** at Year 3 if scaling beyond — Blume, Kalaari, Stellaris, Together Fund — ₹15-30 Cr
- **US/India Series A** at Year 4-5 if going for the bigger play

Avoid:
- US VCs early — they'll push for the wrong market
- Zoho/large strategic investors early — they'll push for acquisition
- Convertible notes with aggressive caps — Indian SAFE/CCD norms favor founders, use them

---

## Part 10 — Why This Is Easier Than Competing With Bitwarden Globally

| Challenge | Global plan | India-first plan |
|---|---|---|
| **Earning trust** | 5-7 years | 2-3 years (no incumbent to displace) |
| **Distribution cost** | $50-200 per paying user | ₹50-200 per paying user (~10-20x cheaper) |
| **First $100k ARR** | 24-36 months | 12-18 months |
| **Compliance complexity** | 10+ jurisdictions | 1 (DPDP) initially |
| **Cultural fluency** | Have to learn each market | Native advantage |
| **Founder loneliness** | Building for users you don't know | Building for users you live among |

The Indian-first path has **lower variance and a clearer near-term path to revenue**. The global-first path has higher variance and higher ceiling but a much longer wilderness period.

You can do this Indian-first plan and still go global in Year 4-5. **You probably can't do the global plan and pivot to India-first later** — by then someone else will have done it.

---

## Part 11 — Honest Risks Specific to India Path

| Risk | Mitigation |
|---|---|
| **Indian users don't pay for software** | Free tier dominance for users; SMBs are the actual revenue base. Don't expect consumer revenue to sustain you. |
| **Zoho launches a real consumer product** | Possible but unlikely — they've had 10 years and haven't. Their DNA is B2B productivity, not consumer security. |
| **Google/Apple OS-level managers are "good enough" for casual Indian users** | True. Compete on features OS managers can't do: cross-platform sharing, family vaults, advanced security, dev tools. |
| **DPDP rules get more restrictive** | Build compliance from day one; you'll be ahead of incumbents who retrofit. Engage with policy via NASSCOM, IFF (Internet Freedom Foundation). |
| **A US/EU player decides to invest in India seriously** | Unlikely (they haven't in 15 years), but if it happens you have head start + cultural moat. |
| **Indian VC market cools further** | Bootstrap as long as possible. Revenue > funding. Have a 3-year survival plan with no outside money. |
| **Government surveillance pressure / decryption demands** | Architecture (zero-knowledge) makes this mostly moot — you can't decrypt user data even if compelled. Document this clearly. Engage with IFF on advocacy. |
| **Cybersecurity skills shortage in India** | Pay above market for security hires. Build remote-friendly culture to access global talent. |

---

## Part 12 — The Single Hardest Thing About This Plan

It requires you to **say no to global ambition early** in exchange for actually winning a market.

Most Indian founders want to be the next Stripe / Notion / Figma — globally famous. The India-first path means you're an Indian company first, possibly forever, possibly with a regional expansion later. That's psychologically harder for ambitious founders than it should be.

But: Razorpay, Zoho, CRED, PhonePe, Postman, Freshworks all started India-first (or used India as the validation market). Most of them are now larger and more profitable than founders who chased global from day one and ran out of runway.

**Owning a market beats chasing one.** India is the second-largest internet user base on Earth, with no entrenched password manager. That's not a consolation prize — that's the prize.

---

## Part 13 — Decision Framework

Use this to choose between the global dev-first plan and the India-first plan:

**Choose India-first if:**
- You're based in India and have a network here
- You have ₹15-25L of runway (savings + part-time work) for 12-18 months
- You're willing to ship in Hindi/regional languages, not just English
- You enjoy/can tolerate Indian compliance work
- You're comfortable being a "regional" player for years before going global
- You want faster path to first revenue

**Choose global dev-first if:**
- You have access to ₹1Cr+ funding from day one
- You have a pre-existing developer following / personal brand
- You have 3-5 years of pure burn before revenue
- You speak English natively and have US/EU tech network
- You want the bigger gamble (higher ceiling, much higher chance of failure)

**Most realistic for you (best guess):**
**India-first → expand regionally → maybe global at Year 5+.** Lower risk, faster validation, defensible niche, and if it works you have something genuinely unique that even global players can't easily copy.

---

## Part 14 — Start Tomorrow (India version)

If you're choosing this path, here's the actual first week:

1. **Buy `securevault.in` domain** (~₹1,500/year). The `.in` matters for trust signal.
2. **Register an Indian private limited company** when revenue is real (defer 6 months; sole proprietorship works initially). Use IndiaFilings or Razorpay Rize for ₹15-30k.
3. **Open a Razorpay account** — sandbox is free, integration takes a day.
4. **Start a `#building-in-public` Twitter/X presence** — post weekly progress in English + Hindi.
5. **Add Hindi locale to the existing mobile app** — even before any other feature work. It's a signal of intent.
6. **Talk to 10 Indian users** — friends, family, college juniors. Watch them try Bitwarden vs your prototype. Note where they get confused.
7. **Read the DPDP Act** end-to-end. It's only ~30 pages. Don't outsource understanding it.
8. **Find one Indian dev community to embed in** — RootConf, IndiaOS, your local meetup. Show up monthly.

---

## Closing

The global plan in `PRODUCT_ROADMAP.md` is a good plan. This is a *better* plan if you're Indian and want to actually win, not just compete.

The market opening is real and time-limited. Within 5 years, either someone builds the Indian password manager, or Indian users settle into Google/Apple/Bitwarden permanently and the window closes. Right now, today, no one is doing this seriously.

That's the kind of opportunity that doesn't appear often. If it resonates, move fast.

> *"Build for the customer in front of you, not the customer you imagine in San Francisco."* — every successful Indian SaaS founder, paraphrased
