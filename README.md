# baseCDS
This a basic but effective software based cross domain solution for onwards development and smaller projects.

# 🛡️ Zero Trust CDS (Software-Based Cross-Domain File Assessor)

This is a **Python-based, open-source, software-defined cross-domain solution (CDS)** for secure file inspection and transfer between domains (e.g., RED → BLUE).

It uses **Magika** (by Google) to accurately detect file types using AI, **regex-based pattern matching** for known threats, and **optional sanitisation** using `bleach`. The project is intentionally light, auditable, and designed for **tactical or sovereign deployments** where full-stack appliances aren't feasible.

---

## ✨ Key Features

- 🔍 **AI-driven file type inspection** via [Magika](https://github.com/google/magika)
- 🧼 Optional **bleach-based sanitisation** for RED → BLUE transfers
- 🧠 Configurable allow/block lists per domain
- 🚨 Deep content scanning using regex for:
  - Script injection
  - SQL injection
  - Shell commands
  - Office macro indicators
  - Encoded payloads
- 📦 Max file size enforcement
- 🔒 Ready for use in Zero Trust pipelines

---

## 🧭 Use Cases

- Cross-domain file transfers in tactical systems
- Pre-ingress validation before delivery to secure enclaves
- Defence, natsec, or sovereign infrastructure deployments
- Sandbox projects for CDS/guard technology prototyping

---

## 🔍 How It Works

 - Blue-side calls blue_call_on_magika()

 - Red-side calls red_call_on_magika()

 - RED → BLUE traffic is additionally sanitised with bleach.clean() after content scan

 - File type is verified with high-confidence (≥ 0.75 by default)

 - Suspicious payloads are rejected or sanitised depending on direction

