# Engagement Terms Template — Loomiq LLC

**Status:** Not legal advice. This template is a starting point Manu can
fill in for the first 3-5 Loomiq engagements. Before scaling past that,
have a lawyer review and customize. Specifically, the liability cap, IP
assignment, and indemnification clauses are conservative defaults that a
real attorney should tune.

**How to use:** copy this file to `~/loomiq-engagements/<customer>-<date>.md`,
fill in every `{{placeholder}}`, export to PDF, and exchange signed copies
via email. DocuSign is fine once the volume justifies it.

---

# Engagement Letter

**Between:** Loomiq LLC, a Delaware limited liability company having an
address at {{loomiq_address}} (the "Consultant")

**And:** {{customer_legal_name}}, a {{customer_entity_type}} having an
address at {{customer_address}} (the "Customer")

**Effective:** {{effective_date}}

---

## 1. Scope of Services

Consultant will perform the **{{engagement_name}}** engagement for
Customer, as described in the deliverables below. The engagement is
**fixed-scope, fixed-fee**, and **fixed-duration**. Out-of-scope work is
itemized separately and requires written agreement before execution.

**Engagement type:**
- [ ] Quick Audit ($2,500 / 5 business days / 1 agent product)
- [ ] EU AI Act Article 14 Evidence Pack ($4,500 / 7 business days)
- [ ] Trust Infrastructure Design Sprint ($9,500 / 10 business days / multi-agent)
- [ ] Other: {{custom_engagement_description}}

**Specific agent product(s) in scope:**

> {{customer_agent_product_name}} — {{one_line_description}}
> Repo / deployment URL: {{repo_or_url}}
> Number of agent products covered: {{count}}

**Start date:** {{start_date}}
**Target completion date:** {{end_date}}

## 2. Deliverables

By the target completion date, Consultant will deliver:

1. **Audit log artifact**: an HMAC-chained JSONL log produced by Quill
   covering the agent product's tool dispatch path for the engagement
   window. The log lives in Customer's environment; Consultant does not
   retain a copy past the readout call.

2. **Executive PDF**: a one-page-per-control evidence pack mapping the
   audit log to the standards Customer selects from:
   EU AI Act (Articles 12, 14, 19), AIUC-1 (Accountability, Reliability,
   Security domains), NIST AI RMF + GenAI Profile, ISO/IEC 42001 A.6.2.8,
   SOC 2 Common Criteria (CC6, CC7, CC8.1, CC9), MITRE ATLAS.

3. **Readout call**: a {{readout_duration}}-minute video call walking
   Customer through the findings, recommendations, and the fix-pack PR
   (if any).

4. **(EU AI Act Evidence Pack only) Self-host configuration**: a Quill
   deployment plan for Customer's VPC including config file, key
   management approach, and retention schedule sized for Customer's
   high-risk classification.

5. **(Trust Infrastructure Sprint only) Trust Ladder per agent**: per-
   agent scope manifests, Permission Decay schedule, A2A Bridge handoff
   edge audit, and Lethal-Trifecta exposure matrix.

## 3. Fees and Payment

**Total fee:** US ${{total_fee}}, fixed.

**Payment terms:** 100% up front via Stripe Payment Link or wire
transfer, due before engagement start. Stripe link will be provided
upon countersignature.

**Refund policy:** If Consultant cannot deliver the agreed scope within
{{refund_window}} business days past the target completion date due
solely to Consultant's actions, Customer receives a pro-rata refund
of the unfulfilled portion. Customer-caused delays (access not granted,
incomplete information, scope changes) do not trigger refund eligibility.

**Out-of-scope work** is billed at $300/hour with a one-week minimum
notice and written acceptance from Customer before any out-of-scope
hours begin.

## 4. Customer Responsibilities

Customer will:

- Provide Consultant with access to the agent product, the deployment
  environment, and relevant documentation within {{access_window}}
  business days of the start date.
- Designate a single point of contact responsible for engagement
  coordination.
- Respond to clarification requests within one business day during
  the engagement window.
- Review and provide feedback on draft deliverables within
  {{review_window}} business days.

Delays in any of the above shift the target completion date by an
equivalent amount without penalty to Consultant.

## 5. Intellectual Property

**Quill itself remains MIT-licensed open source** at
github.com/manumarri-sudo/quill. Nothing in this engagement transfers
any rights in Quill to Customer beyond what the MIT license already
grants.

**Customer-specific deliverables** (the audit log, the executive PDF,
the fix-pack PR, any custom policy overrides written for Customer's
stack) are owned by Customer upon full payment.

**Pre-existing tools, methods, and templates** Consultant uses to
produce the deliverables remain Consultant's property. This includes
the AIUC-1 control crosswalk, the evidence-pack rendering pipeline,
and any internal Loomiq playbooks.

**Permission to publish**: Customer grants Consultant the right to
reference Customer's name and a one-paragraph anonymized engagement
description in Loomiq's marketing materials, provided no confidential
findings or proprietary data are disclosed. Customer may decline this
permission by checking the box: [ ] No publication permission.

## 6. Confidentiality

Each party will treat the other party's non-public information as
confidential and will not disclose it to third parties for two years
following the engagement end date.

Specifically, Consultant will:
- Not retain copies of Customer's audit log or codebase past the
  readout call.
- Not use Customer's audit log data to train any machine learning model.
- Not disclose Customer's name, agent product, or any engagement
  details to any party other than as permitted under Section 5.

Specifically, Customer will:
- Not share Consultant's deliverable templates, control crosswalks, or
  internal documents with third-party consultants without written
  permission.

## 7. Warranties and Disclaimers

Consultant warrants that:
- The engagement will be performed in a professional and workmanlike
  manner consistent with industry standards.
- The deliverables will be original works of Consultant or properly
  licensed third-party works (Quill is MIT; all other Loomiq materials
  are original).

**Consultant does NOT warrant that:**
- The engagement deliverables will satisfy any specific regulator,
  auditor, or insurance underwriter without their independent review.
- Quill will catch every possible dangerous AI agent action. Quill is
  governance plumbing, not AI safety; it pairs with model-level
  guardrails, not replaces them.
- Customer's AI agent product is or will be compliant with EU AI Act,
  AIUC-1, NIST AI RMF, ISO/IEC 42001, SOC 2, or any other regulatory
  framework on the basis of this engagement alone. Compliance is a
  full-organization attestation; the engagement produces one evidence
  source within it.

EXCEPT AS EXPRESSLY PROVIDED, THE SERVICES AND DELIVERABLES ARE
PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

## 8. Limitation of Liability

EACH PARTY'S TOTAL LIABILITY UNDER THIS AGREEMENT IS LIMITED TO THE
FEES PAID BY CUSTOMER TO CONSULTANT UNDER THIS AGREEMENT.

NEITHER PARTY IS LIABLE FOR INDIRECT, CONSEQUENTIAL, INCIDENTAL,
SPECIAL, OR PUNITIVE DAMAGES, INCLUDING LOST PROFITS, LOST REVENUE,
OR LOSS OF DATA, EVEN IF ADVISED OF THE POSSIBILITY.

This limitation does not apply to: (a) Customer's payment obligations;
(b) either party's confidentiality obligations under Section 6;
(c) either party's indemnification obligations under Section 9;
(d) gross negligence or willful misconduct.

## 9. Indemnification

Each party will indemnify, defend, and hold harmless the other party
from third-party claims arising from the indemnifying party's gross
negligence or willful misconduct in connection with this engagement.

## 10. Term and Termination

This agreement begins on the Effective Date and ends upon the later of:
(a) delivery of all deliverables and Customer payment of the full fee,
or (b) {{outer_term_date}} ({{outer_term_days}} days past target
completion).

Either party may terminate for material breach upon 10 days' written
notice if the breach is not cured within the notice period.

Upon termination, Customer pays for work performed through the
termination date on a pro-rata basis, and Consultant delivers all
in-progress work product to Customer.

## 11. Miscellaneous

**Governing law:** This agreement is governed by the laws of the
State of Delaware, without regard to its conflict-of-laws principles.

**Disputes:** The parties will first attempt to resolve any dispute
through good-faith negotiation for 30 days. Unresolved disputes will
be settled by binding arbitration in {{arbitration_venue}} under the
{{arbitration_rules}} rules.

**Entire agreement:** This document is the entire agreement between
the parties regarding the engagement and supersedes any prior
discussions or writings.

**Amendments:** Modifications require a writing signed by both parties.

**Assignment:** Neither party may assign this agreement without the
other party's prior written consent, except to a successor in
connection with a merger or sale of substantially all assets.

## Signatures

**Loomiq LLC**

By: ________________________________
Name: Manu Marri
Title: Founder
Date: ________________

**{{customer_legal_name}}**

By: ________________________________
Name: {{customer_signatory_name}}
Title: {{customer_signatory_title}}
Date: ________________

---

## Reminder: lawyer-review checklist

Before scaling past the first 3-5 engagements, have an attorney review:

- [ ] Liability cap appropriate for the deal size and risk profile
- [ ] IP assignment language matches Manu's actual practice (Loomiq playbooks vs. Quill open source vs. customer-specific deliverables)
- [ ] Indemnification scope and exclusions
- [ ] Confidentiality term length (2 years is conservative)
- [ ] Governing law venue (Delaware default is reasonable but the customer's HQ state may be appropriate)
- [ ] Arbitration vs. court (arbitration faster, court appealable)
- [ ] Permission-to-publish language (current default opt-in; some legal counsel will want opt-out)
- [ ] EU customers may require GDPR-specific addenda (data processor agreement)
- [ ] California customers may require CCPA-specific addenda
- [ ] Stripe Payment Link refund flow alignment with Section 3 refund language
