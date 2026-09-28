# Application specialist review: would the AI still understand the task?

**For someone who knows application support or engineering work, with no Hylja background. Allow 20–30 minutes.** All examples below are made up. Please do not use real customer, employee, infrastructure or credential details in your reply.

## Why we need your help

Hylja is an early-stage tool intended to hide protected details before an AI assistant sees them while preserving enough meaning for an engineering task. The AI in these examples **drafts an answer only**; it does not contact anyone or change a system. If an authorized person later needs an original contact detail, a separate approved process would be needed. We are deciding **what kinds of information to recognize** and **which details an AI answer must keep correct**. Before we set the expected answers for made-up tests, we need you to spot wrong assumptions and missing cases.

You do **not** need to read code, a pull request, standards or security policy. Judge the five proposals below using your work experience. For each one, choose **Makes sense**, **Needs change** or **Outside my expertise**. If you choose **Needs change**, one sentence or a small made-up counterexample is enough.

## Five proposals to challenge

1. **Shared mailbox.** `support@example.invalid` may be used by several people. We treat it as an email address, not as a person. We leave open whether it identifies a particular person in its context. Does that distinction make sense?
2. **Part reference versus parts list.** `PART-EXAMPLE-A` points to an item. A bill of materials lists components and quantities, even if it contains no part number. We treat the reference and the actual engineering description as different kinds of information. Does that match how you work?
3. **Support handoff.** A made-up note says “Person A is primary; Person B is backup.” An AI drafting the handoff needs to keep **who is first and who is backup**, even if it does not see the original names or email addresses. Which *one or two other facts* would the draft need to be useful? The AI does not send the handoff.
4. **Diagnostic answer.** A made-up log says a client tried HTTPS port **443**, but the service expects **8443**. A credential is replaced by `[protected:API_KEY]`. If a separate policy check permits this task, an AI explaining the likely mismatch needs the exact ports and the fact that a credential was supplied, but not its value. Which *one or two other facts* would the diagnosis need, such as the observed error or authentication result?
5. **JSON configuration.** An AI is asked to discuss this made-up configuration after names are hidden:

   ```json
   {"customer":"Customer A","service":"Service A","note":"Customer A checks Service A","endpoint":"https://service.example.invalid/v1/ping","outputFile":"/tmp/report.json","os":"linux"}
   ```

   We would check that the **hidden JSON given to the AI** stays valid; `https` without an explicit port still means effective port **443**; `/v1/ping` and the Linux absolute output path remain meaningful; and repeated references to this customer or service within this task use the same stand-in. Are these the right checks for a useful answer? What essential check is missing?

**One missing case:** What important application or engineering situation would these five examples miss? A short description with made-up values is enough.

**Overall:** Are the details we keep in examples **3–5** a sensible starting point for those tasks? Choose **Yes**, **Yes with changes**, **No** or **Outside my expertise**. You are not being asked to judge every engineering domain.

You can copy this into your reply:

```text
1. Makes sense / Needs change / Outside my expertise — ...
2. Makes sense / Needs change / Outside my expertise — ...
3. Makes sense / Needs change / Outside my expertise — ...
4. Makes sense / Needs change / Outside my expertise — ...
5. Makes sense / Needs change / Outside my expertise — ...
Missing case: ...
Overall for examples 3–5: Yes / Yes with changes / No / Outside my expertise — ...
```

## What happens with your reply

Reply privately to the person who sent you this brief, using the channel they gave you. If they did not give you one, ask them for a private reply channel; do not post your reply on GitHub. We will turn each correction into a revised proposal and send you a short summary of what changed, so you can check whether we addressed it. If you helped write or direct these proposals, or worked on the software being tested, tell the sender privately so we can check independence.

Your review checks **whether the categories and answers make sense for application work**. The project team checks sources and code. Other qualified reviewers decide privacy rules, what information an AI may receive, and how tests are scored. Your short reply helps us revise the proposal; it does not formally approve the design or tests.

Optional background only: the [full independent-review handoff](issue-65-66-independent-review-handoff-p0.1.md) and [provisional design interview notes](issue-65-66-grill-working-notes-p0.1.md). Neither is required to answer this page.
