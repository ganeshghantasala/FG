# FakeGuard — 9 AM Demonstration Script

## 1. One-sentence pitch
"FakeGuard is a hybrid phishing-analysis engine that does not rely on a single URL score: it combines URL ML evidence, webpage behavior evidence, and deception/identity indicators, then performs cross-signal contradiction analysis to generate an explainable risk report."

## 2. Demonstration
1. Start the server.
2. Open http://127.0.0.1:5000
3. Analyze a known legitimate site you are authorized to test.
4. Analyze a deliberately suspicious URL or a locally prepared HTML test page.
5. Show the three component scores:
   - URL ML risk
   - HTML behavior risk
   - identity/deception risk
6. Point out the evidence list.
7. Demonstrate the contradiction case:
   a URL can look ordinary while the page requests passwords and sends a form to another domain.
8. Explain that FakeGuard raises review risk when independent evidence streams disagree in a suspicious direction.

## 3. Faculty explanation
Existing literature already contains URL-only ML, URL+HTML classifiers, SHAP-based explainability, and multimodal URL/HTML/image systems. Therefore our contribution is not "we use Random Forest" or "we use HTML."

Our proposed research contribution is the evidence-fusion layer:
- independently score URL, page behavior and deception signals;
- retain the individual evidence instead of hiding everything inside one model;
- calculate a cross-signal contradiction/consistency signal;
- produce an actionable, human-readable explanation and structured report.

## 4. Do NOT say
- "This is definitely patentable."
- "Nobody has ever done this."
- "Our accuracy is 99%" unless you have measured it on a proper held-out dataset.
- "The system guarantees a website is safe."

## 5. Say instead
"This is our proposed architecture and prototype. We identified relevant prior art and are positioning the evidence-fusion/contradiction mechanism as the research contribution. Formal novelty, inventive step and patentability require a professional prior-art search and patent examination."

## 6. Current limitation
Domain age, DNS reputation, traffic and PageRank are not inferred when live external intelligence is unavailable. They are kept neutral rather than fabricated. This is an intentional design choice.
