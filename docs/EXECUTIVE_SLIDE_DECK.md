# Executive Slide Deck — Utah Common Login & Smart Access Control

> **Audience**: Non-Technical Managers, Division Directors, Program Leads, and Project Stakeholders (Utah DNR / DWRi / DWRe)  
> **Purpose**: Explain *what* this solution does, *why* it was needed, the *core security principles* behind it, and *how* the technologies work in plain English.

---

## Slide 1: Executive Overview — "One Front Door & Smart Badge" for Utah Water Applications

### The Big Picture
Our new **Common Authentication & Authorization Service** replaces 40+ aging, disconnected permission lists across Utah water applications with a single, modern security hub built for **State Staff, 55 River Commissioners, Public Water Suppliers, Scientists, and Citizens**.

### The Everyday Analogy
* **Old Way (40 Metal Keys & Clipboards)**: Every water application kept its own separate list of who was allowed inside.
* **New Way (One Universal Smart Badge)**: Utah now has **one central security desk** that checks a person's identity (via UtahID or partner login) and issues a **temporary smart badge** programmed for their exact river basin, regional office, and season.

### Key Executive Metrics
* **4 Silos → 1 Hub**: Unifies `wrsysDB`, `DVRTEDIT`, `Water Use Program`, and `HydroServer` into one central database.
* **62 Roles → 1 Reusable Role**: Collapses 62 hardcoded river-basin role names into a single reusable *Water Commissioner* role paired with a geographic river boundary.
* **15-Minute Digital Passes**: Replaces risky IP-address tracking with encrypted, short-lived passes bound to the individual user.
* **100% Auditable**: Every permission records *who* granted it, *why*, and *when* it automatically expires.

---

## Slide 2: Why We Needed This — Legacy Silos vs. Unified Zero Trust Hub

![Utah Water Applications: Legacy Silos vs. Unified Zero Trust IAM Hub](./images/01-legacy-vs-zero-trust-transformation.jpg)

*(Based on the 2026 DWRi Technical Debt Plan & Roles Architecture Assessment)*

1. **The "Conference Wi-Fi" Login Risk (IP Session Hijacking)**
   * **What happened**: The legacy login portal stored a user's building internet address (IP) in a database table to remember who was logged in.
   * **Why it matters**: If a staff member logged in from a hotel, conference, or shared Wi-Fi network, *anyone else on that same Wi-Fi* could open the website and inherit that employee's identity and edit permissions.
2. **Four Disconnected Permission Islands**
   * **What happened**: Permissions were split across four separate databases (`wrsysDB`, `DVRTEDIT`, `Water Use`, and `HydroServer`).
   * **Why it matters**: Onboarding or offboarding an employee required checking four separate systems with no central visibility.
3. **"101 Manual Rows" & Permission Creep (No Groups)**
   * **What happened**: The legacy system had no "Staff Groups." Setting up 6 Regional Office employees required manually entering **101 individual database rows**.
   * **Why it matters**: Permissions accumulated over decades without cleanup—just two veteran employees held **30% of all access grants** across the division.
4. **62 Copy-Pasted River Role Names & No Expiration Dates**
   * **What happened**: Because the old database couldn't attach a geographic boundary to a role, IT had to invent 62 separate role names (`"Edit: WEBER RIVER"`, `"LOWER BEAR - IDAHO"`), and seasonal deputies or contractors stayed active indefinitely unless manually deleted.

---

## Slide 3: Core Principle #1 — Two-Stage Zero Trust Architecture (The Airport Analogy)

![Utah Common Authentication & Authorization — Two-Stage Zero Trust Architecture on GCP](./images/02-gcp-zero-trust-system-architecture.jpg)

Technology teams often use two words that sound similar—**Authentication (AuthN)** and **Authorization (AuthZ)**—but they solve two very different business problems. Think of Salt Lake City International Airport:

| Concept | Question It Answers | Airport Analogy | How Our Solution Works |
| :--- | :--- | :--- | :--- |
| **1. Authentication (AuthN)** *(Stage 1: Token Exchange)* | *"Who are you?"* | Showing your Driver's License at the **TSA Security Check** | State employees & citizens log in with **UtahID**. External water districts, cities, and USGS researchers log in with their own organization accounts (Microsoft, Google, ORCID). **We never store passwords.** |
| **2. Authorization (AuthZ)** *(Stage 2: Policy Decision Point)* | *"What are you allowed to do right now?"* | Scanning your **Boarding Pass at Gate B14** | Being inside the airport doesn't let you fly the plane! When a user clicks "Edit Station" in a Utah water app, our service checks their exact role, river basin boundary, and active dates in under 10 milliseconds. |

---

## Slide 4: Core Principle #2 — What "Zero Trust" Means for Managers

**"Zero Trust" does not mean we distrust our employees.** It means the software never assumes someone has access just because they are on an office network or logged in earlier today.

* **Old "Castle-and-Moat" Model**: Once you cross the drawbridge (log in once), you have broad access all day long.
* **New "Zero Trust Smart Badge" Model**:
  1. **Default Closed**: Unless a policy explicitly grants access, the door stays locked.
  2. **App-Specific 15-Minute Passes**: A digital pass issued for the *Water Measurement Dashboard* cannot be used to access an unrelated application.
  3. **Automatic Seasonal Expiration**: A Deputy Commissioner appointed from *April 15 to October 31* loses edit access automatically at midnight on November 1—zero IT tickets required.
  4. **Emergency Brake (`Explicit Deny`)**: When separation of duties requires blocking a specific action, an explicit "Deny" rule overrides any other permission.

---

## Slide 5: Core Principle #3 — The 3 Building Blocks & 6-Step Decision Pipeline

![Hybrid RBAC + Hierarchical ltree Scope + ABAC Policy Decision Engine](./images/03-hybrid-rbac-ltree-abac-engine.jpg)

Instead of creating dozens of custom roles for every river and regional office, every permission grant combines three building blocks:

$$\text{Smart Access Grant} = \textbf{1. Role (Job)} + \textbf{2. Scope (Where)} + \textbf{3. Guardrails (Conditions)}$$

1. **Role (What is your job?)**: Reusable job functions like *Water Commissioner*, *Automation Engineer*, *Public Water Supplier*, or *Data Steward*.
2. **Scope (Where do you work?)**:
   * **Tier A — Statewide / App-Global**: Across the entire application.
   * **Tier B — Regional Office Hierarchy (`ltree`)**: Granting access at the *Northern Regional Office (Logan)* automatically covers sub-teams in that region.
   * **Tier C — Single Resource Boundary**: Scoped to one specific river system (e.g., `weber-river`) or water supplier (`jvwcd`).
3. **Safety Guardrails (Under what conditions?)**:
   * Require **2-Factor Authentication (MFA)** before deleting raw sensor readings or changing cell modem IP addresses.
   * Restrict sensitive administrative actions to verified **State Employees** within active seasonal dates (`starts_at` → `expires_at`).

---

## Slide 6: Meet the 6 Real-World Utah Water Personas

![Utah Division of Water Rights (DWRi) — The 6 Real-World Water Personas & Zero Trust Guardrails](./images/04-utah-dwri-six-personas-matrix.jpg)

*(Directly aligned with the 72-page 2026 DWRi User-Centric Design Study & Figma Prototypes)*

| Persona | Who They Are in Utah | What They Can Do | Built-In Guardrail |
| :--- | :--- | :--- | :--- |
| **1. Donna** *(Director, Legislator, Citizen)* | Directors, Legislative Auditors, General Public | View published stations, FAIR data dictionary, legislative KPIs, and public data exports. | Read-only on published data; internal field photos and gate codes are hidden. |
| **2. Wiley & Parker** *(Water User & Water Supplier)* | Farmers, Canal Co. (Wiley); Cities, JVWCD, CUWCD (Parker) | Wiley manages "My Sites" favorites & flow alerts. Parker submits annual water use reports & proposes service boundaries. | Favoriting a station never grants edit rights. Parker is locked strictly to their own water district. |
| **3. Sarah** *(Scientist & Consultant)* | USGS, BOR, USU, OpenET, Engineering Consultants | Queries provisional vs. best-available research datasets and manages personal API tokens. | Self-service API keys are read-only; external consultant passes auto-expire. |
| **4. Cody** *(55 Water Commissioners & Deputies)* | Kent Wilkerson (Weber), Porter Monroe (Lower Sevier), etc. | Edits field measurements and stations on their appointed river system; syncs offline mobile drafts. | Scoped strictly to their assigned `distribution_system`; seasonal deputies auto-expire Oct 31. |
| **5. Fatima** *(4 Specialized Engineer Profiles)* | Distribution, Automation, Regional (7 offices), & Modeling Engineers | Distribution manages sites/ratings; Automation manages cell modems & raw data withdrawal; Regional supervises regions; Modeling syncs WCAT models. | Modeling Engineers cannot touch station hardware or delete raw data; Automation Engineers must pass **MFA** for raw data deletion. |
| **6. Diego** *(Data Steward & Water Use Manager)* | Data Services Section (QA/QC) & Water Use Reviewers | Manages statewide vocabularies, QA/QC rules, and user assignments; reviews water supplier submissions. | Requires **State Employee + MFA**. Water Use Managers are explicitly blocked from editing supplier boundaries. |

---

## Slide 7: Plain-English Technology Translator for Leadership

Why we chose these specific technologies—and what they mean for **budget, reliability, and staffing**:

| Technology | Plain-English Role | Why It Benefits Utah Management |
| :--- | :--- | :--- |
| **Go (Golang)** | *The High-Speed Engine* | Created by Google for cloud security services. Starts in milliseconds, uses minimal memory (keeping monthly cloud bills low), and is easy to maintain long-term. |
| **Google Cloud Run** | *Auto-Scaling Serverless Hosting* | Automatically scales up during peak spring runoff/irrigation season and scales down when quiet. **Zero physical servers for IT staff to patch or reboot.** |
| **Cloud SQL for PostgreSQL (`ltree`)** | *The Enterprise Vault & Org Chart* | Industry-standard relational database with automated backups and built-in hierarchy math (`ltree`) that mirrors DNR's exact division and regional office structure. |
| **OIDC & Token Exchange (RFC 8693)** | *Universal Digital Passport* | Open government security standard that connects seamlessly with **UtahID** for state staff and Microsoft/Google/ORCID for external partners without storing passwords. |

---

## Slide 8: Strategic Return on Investment (ROI) & Rollout Plan

### How This Saves Time & Budget Across Future Projects
* **"Build Once, Plug In Anywhere"**: Future map portals, modeling tools, and mobile apps no longer spend months building custom login and permission databases. They connect to this service in days.
* **No Code Releases for Admin Changes**: Adding a new application, onboarding a regional group, or appointing a seasonal deputy happens instantly via the administration interface.
* **Instant Audit Readiness**: Answers legislative audit requests immediately with a complete record of *who* has access, *who* approved it, *why*, and *when* it expires.

### Phased Rollout Roadmap
1. **Phase 1 — Foundation Complete (Today)**: Core Zero Trust service, database schema, 6 DWRi Personas, and automated verification suite (100% passing) ready for deployment.
2. **Phase 2 — Pilot Deployment**: Deploy to GCP Cloud Run and connect the 2026 DWRi Water Measurement Data Dashboard & Utah Water Resources Map App.
3. **Phase 3 — Unify Legacy Stores**: Gradually migrate `DVRTEDIT`, `Water Use Program`, `HydroServer`, and `wrsysDB` behind the central service.
4. **Phase 4 — Retire Legacy IP Login Table**: Decommission the legacy IP-based session table and shared workstation accounts.
