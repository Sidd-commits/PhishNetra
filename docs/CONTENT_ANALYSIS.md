# PhishNetra — Web Content Analysis & Detection Heuristics

**Milestone:** Implementation 3 (Secure Web Content Analysis & AI-Assisted Phishing Detection)  
**Components:** `services/ml/app/analyzer/` & `services/ml/app/features/`

---

## 1. Overview

Content-level analysis inspects the rendered HTML DOM, form definitions, embedded scripts, visible text, and brand identifiers. This enables detection of phishing pages hosted on compromised legitimate domains or dynamic single-page applications where the URL alone appears benign.

---

## 2. Analysis Modules & Heuristic Signals

### 2.1 DOM Structural Analyzer (`dom_analyzer.py`)
Parses HTML content using streaming SAX/HTMLParser to extract structural metrics:
- **`dom_size`**: Total number of DOM elements.
- **`forms_count`**: Total `<form>` elements.
- **`input_count`**: Total `<input>`, `<select>`, `<textarea>` elements.
- **`password_inputs`**: Count of `<input type="password">` elements.
- **`hidden_inputs`**: Count of `<input type="hidden">` elements.
- **`iframe_count`**: Total `<iframe>` elements.
- **`external_iframe_count`**: IFrames sourced from third-party domains.
- **`hidden_iframe_count`**: IFrames rendered with zero width/height or `display:none`.
- **`script_count`**: Total `<script>` elements.
- **`external_script_count`**: Scripts loaded from external origins.

### 2.2 Form & Credential Harvest Analyzer (`form_analyzer.py`)
Forms are the primary mechanism for credential theft in phishing attacks.
- **Field Type Detection:** Detects password fields, email/username inputs, credit card numbers, CVVs, and OTP/2FA input fields.
- **Action Origin Inspection:** Analyzes `form.action`:
  - `SAME_ORIGIN`: Submits to same hostname or subdomain.
  - `CROSS_ORIGIN`: Submits credentials to an external third-party domain.
  - `RAW_IP`: Submits credentials directly to a bare IP address (e.g. `http://192.168.1.50/submit.php`).
  - `SUSPICIOUS_PATH`: Submits to generic backend endpoints (`submit.php`, `login.php`, `verify.php`, `gate.php`).
- **Risk Impact:** A login form submitting credentials to a cross-origin domain or raw IP generates a **CRITICAL** risk signal (`is_credential_form = true`, `is_cross_origin = true`).

### 2.3 Static JavaScript Heuristics (`js_analyzer.py`)
Applies lightweight static analysis to script content without full code execution:
- **`has_eval`**: Usage of `eval()` or `Function()` constructor.
- **`has_document_write`**: Usage of `document.write()` to dynamically inject HTML.
- **`has_unescape`**: Usage of `unescape()` or `decodeURIComponent()` for string decoding.
- **`has_location_manipulation`**: Script modifications to `window.location`, `location.replace()`, or `location.href`.
- **`has_obfuscated_strings`**: Detection of packed JavaScript, heavy hex arrays (`\x41\x42`), large base64 strings, or extreme Shannon entropy in script text.

### 2.4 Brand Impersonation & Domain Consistency (`brand_analyzer.py`)
Maintains an extensible catalog of 15 high-value targeted brands (Microsoft, Google, Apple, Amazon, PayPal, Netflix, Chase, Bank of America, Wells Fargo, Meta/Facebook, Instagram, LinkedIn, Adobe, Dropbox, DocuSign) with their legitimate domain registries.
- **Brand Reference Detection:** Identifies brand names and logos in page title, headers (`<h1>`-`<h3>`), form actions, and body text.
- **Brand-Domain Consistency Check:** If a page references a known brand (e.g. `"Microsoft Account Login"`) but is hosted on an unregistered/unrelated domain (e.g. `random-phish-domain.com`), the engine triggers:
  ```json
  {
    "featureKey": "brand_domain_mismatch",
    "featureValue": true,
    "severity": "CRITICAL",
    "description": "Page explicitly references 'Microsoft' while hosted on unrelated domain 'random-phish-domain.com'"
  }
  ```

### 2.5 Phishing Keywords & Social Engineering Urgency (`brand_analyzer.py`)
Categorizes visible page text across risk domains:
- **`AUTH`**: `login`, `sign in`, `password`, `verify account`, `confirm identity`, `session expired`.
- **`SECURITY`**: `security alert`, `unauthorized access`, `account suspended`, `locked`, `breach`.
- **`FINANCIAL`**: `billing`, `invoice`, `payment failed`, `update payment method`, `refund`.
- **`URGENCY`**: `urgent`, `immediately`, `within 24 hours`, `action required`, `limited time`.
- **Urgency Score:** Normalized 0.0 – 1.0 index indicating the intensity of social engineering pressure.

---

## 3. Normalized Content Feature Vector

The extracted metrics are converted into a standardized 20-dimensional numerical feature vector:

| Index | Feature Key | Type | Description |
| :---: | :--- | :---: | :--- |
| 0 | `forms_count` | Integer | Total forms on page |
| 1 | `password_inputs` | Integer | Password field count |
| 2 | `hidden_inputs` | Integer | Hidden input count |
| 3 | `has_login_form` | Binary (0/1) | Whether a login form is present |
| 4 | `external_form_actions` | Integer | Forms submitting cross-origin |
| 5 | `ip_form_actions` | Integer | Forms submitting to raw IP |
| 6 | `iframe_count` | Integer | Total iframe count |
| 7 | `external_iframe_count` | Integer | Third-party iframe count |
| 8 | `hidden_iframe_count` | Integer | Hidden iframe count |
| 9 | `script_count` | Integer | Total script count |
| 10 | `external_script_count` | Integer | External script count |
| 11 | `external_domain_count` | Integer | Unique remote domains contacted |
| 12 | `has_eval` | Binary (0/1) | Usage of `eval()` |
| 13 | `has_document_write` | Binary (0/1) | Usage of `document.write()` |
| 14 | `has_obfuscated_strings` | Binary (0/1) | Presence of obfuscated script blocks |
| 15 | `suspicious_keyword_count` | Integer | Count of matched phishing keywords |
| 16 | `urgency_score` | Float (0-1) | Urgency / social engineering score |
| 17 | `brand_reference_count` | Integer | Number of brand references found |
| 18 | `brand_domain_mismatch` | Binary (0/1) | Brand detected on foreign domain |
| 19 | `redirect_count` | Integer | Redirection hops traversed |

---

## 4. Content Risk Synthesis & Baseline Model

The feature vector is evaluated by `content_model.py` which computes a content risk score and phishing probability:
- Base score is computed via weighted feature aggregation.
- High-severity override rules are applied (e.g. brand-domain mismatch + password form = `phishingProbability >= 0.88`).
- Content risk and findings are returned to the Node.js API where they are incorporated into the 8-layer composite risk engine.
