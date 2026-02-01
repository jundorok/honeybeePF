# eBPF Observability Platform

**Lightweight eBPF observability for AI workloads (GPU & token usage)**

---

## 1. Project Overview
A lightweight, eBPF-based observability platform designed to identify cost and performance bottlenecks in AI workloads by selectively collecting essential data such as GPU utilization and token usage.

---

## 2. Background / Introduction
Traditional observability tools often introduce significant operational overhead due to excessive resource consumption, required application code changes, and complex configuration processes.  

To address these limitations, our platform is built around a Rust-based eBPF agent that collects only essential data at the kernel level without any code modifications.  

The agent can be deployed via Helm Charts in Kubernetes environments or as a standalone binary in traditional AI data centers, enabling cost reduction and performance optimization across heterogeneous infrastructures.

---

## 3. Core Values
- We practice selective observability—collecting only decision-driving data directly from the kernel.  
- Minimal overhead by design  
- Infrastructure-agnostic: works on Kubernetes and traditional AI data centers  
- Built for AI efficiency: enabling cheaper, faster, and more efficient AI workloads  

---

## 4. Team

| Name   | ID | Role       | SNS | Responsibilities                 |
|--------|----|------------|-----|---------------------------------|
| Jundorok |    | Team Leader | TBU | Roadmap & Feature Development   |
| pmj-chosim |    | Core Dev   | TBU | CI/CD & Observability           |
| sammiee5311 |    | Core Dev   | TBU | Feature Development             |
| vanillaturtlechips |    | Core Dev   | TBU | CI/CD & Observability           |

---

## 5. Tech Stack
- **Languages:** eBPF, Kernel, Rust  
- **Infrastructure:** Kubernetes, Helm, OpenTelemetry, Prometheus, Grafana  
- **Communication:** Discord, GitHub  

---

## 6. Roadmap
- **Phase 1:** CI/CD and Observability Setup  
- **Phase 2:** Core Module Development  
- **Phase 3:** Monitoring and Testing  
- **Phase 4:** Release  

---

## 7. How to Contribute
- **Issues:** Use GitHub Issues for bug reports or feature requests  
- **PRs:** Contributions must open PRs  
- **Guide:** TBU  

---

## 8. Resources & Links
- GitHub Repository: [*Link*]

---

