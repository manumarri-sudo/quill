# Future Loomiq SaaS / consulting landing page

This directory holds artifacts for the **paid Loomiq consulting and SaaS
business** that sits downstream of the Quill open-source launch. Do
not deploy any of these yet.

## Why this is parked

Quill is launching as a free, MIT, open-source tool first. The strategic
sequence is:

1. **OSS launch wave** (now → next 4 weeks): get the tool into developers'
   hands, build GitHub stars, accumulate user stories, capture early
   feedback. The README + the Substack post + the Show HN post + the
   PyPI listing are the only "landing pages" that matter right now.
2. **Credibility accumulation** (weeks 4–12): one or two auditor /
   underwriter quotes, one named reference customer, a small
   third-party security review. None of this requires the paid
   landing page.
3. **Paid surface launch** (weeks 12+): once the OSS surface has
   converted the first ~100 GitHub stargazers and ~10 production
   installs into a verifiable user base, *then* the Loomiq landing
   page goes live with the Evidence Pack / Quick Audit / Trust
   Sprint SKUs.

Charging on Day 1 while the project is still proving itself
distribution-wise would split the marketing message and confuse the
audience. The OSS launch story is "install in 30 seconds." The paid
story is "we'll do this for you in a week." Mixing them dilutes both.

## What's in this directory

- **`landing-page/index.html`** — single-file Loomiq landing page with
  three SKU cards, August 2 deadline banner, founder bio, FAQ. Ready
  to deploy when the time comes; placeholders for Stripe Payment Links
  and Calendly URL.

## When to ship the paid surface

Trigger conditions (any one is sufficient):

- 100 GitHub stars on the Quill repo
- One unsolicited "this saved me" story from a non-Manu user
- A reply from any of the six auditor / insurer cold outreach emails
  (`docs/marketing/outreach/auditor-and-insurer-emails.md`)
- A PR from a non-Manu contributor that adds value
- One named pilot customer with permission to be on the landing page

When any of those land, do the following in order:

1. Create the three Stripe Payment Links (Stripe Dashboard → Payment
   Links → New, with the SKU details from the landing page)
2. Create the Calendly / Cal.com 20-minute booking event
3. Replace the four `REPLACE_WITH_*` placeholders in
   `landing-page/index.html`
4. Add the case study / quote / logo to the landing page
5. Deploy to `loomiq.com` (Vercel + GitHub auto-deploy is the fastest
   path; `npx vercel --prod` from this directory works)
6. Send the Substack announcement + LinkedIn post + first email batch
   to existing followers / DMs

## Don't deploy this prematurely

The biggest single risk for this project right now is positioning
confusion. The OSS Quill is the product. The paid Loomiq services are
the secondary monetization path. If the landing page goes live before
the OSS has traction, every visitor wonders whether they should pay
for what they thought was free. Hold the line until the OSS surface
has converted some volume.
