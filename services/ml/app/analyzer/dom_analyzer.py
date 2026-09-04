"""
PhishNetra - Secure DOM & Structural Analysis Engine
Module: services.ml.app.analyzer.dom_analyzer
Milestone: 3
"""

from html.parser import HTMLParser
from typing import Dict, Any, List, Optional
import urllib.parse
import re


class DOMParser(HTMLParser):
    """
    Safe streaming SAX-style HTML parser for structural feature extraction.
    Resistant to billion laughs and malformed markup.
    """

    def __init__(self, base_url: str = ""):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.node_count = 0
        self.max_depth = 0
        self.current_depth = 0

        self.title = ""
        self.in_title = False

        self.meta_tags: List[Dict[str, str]] = []
        self.forms: List[Dict[str, Any]] = []
        self.current_form: Optional[Dict[str, Any]] = None

        self.iframes: List[Dict[str, str]] = []
        self.scripts: List[Dict[str, Any]] = []
        self.in_script = False
        self.current_script_attrs: Dict[str, str] = {}
        self.current_script_content = ""

        self.links: List[Dict[str, str]] = []
        self.current_link: Optional[Dict[str, str]] = None

        self.text_accumulator: List[str] = []
        self.in_ignore_tag = False
        self.ignore_tags = {"script", "style", "noscript", "svg"}

    def handle_starttag(self, tag: str, attrs_list: List[tuple]):
        self.node_count += 1
        self.current_depth += 1
        if self.current_depth > self.max_depth:
            self.max_depth = self.current_depth

        tag_lower = tag.lower()
        attrs = {k.lower(): (v or "") for k, v in attrs_list}

        if tag_lower in self.ignore_tags:
            self.in_ignore_tag = True

        if tag_lower == "title":
            self.in_title = True

        elif tag_lower == "meta":
            self.meta_tags.append(attrs)

        elif tag_lower == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").upper(),
                "name": attrs.get("name", ""),
                "id": attrs.get("id", ""),
                "target": attrs.get("target", ""),
                "inputs": []
            }

        elif tag_lower == "input":
            input_dict = {
                "type": attrs.get("type", "text").lower(),
                "name": attrs.get("name", ""),
                "id": attrs.get("id", ""),
                "placeholder": attrs.get("placeholder", ""),
                "autocomplete": attrs.get("autocomplete", ""),
                "value": attrs.get("value", "")
            }
            if self.current_form is not None:
                self.current_form["inputs"].append(input_dict)
            else:
                # Standalone input outside a form
                self.forms.append({
                    "action": "",
                    "method": "GET",
                    "name": "orphan_form",
                    "id": "",
                    "target": "",
                    "inputs": [input_dict]
                })

        elif tag_lower == "iframe":
            self.iframes.append({
                "src": attrs.get("src", ""),
                "width": attrs.get("width", ""),
                "height": attrs.get("height", ""),
                "style": attrs.get("style", ""),
                "hidden": "hidden" in attrs or "display:none" in attrs.get("style", "").lower()
            })

        elif tag_lower == "script":
            self.in_script = True
            self.current_script_attrs = attrs
            self.current_script_content = ""

        elif tag_lower == "a":
            self.current_link = {
                "href": attrs.get("href", ""),
                "text": ""
            }

    def handle_endtag(self, tag: str):
        self.current_depth = max(0, self.current_depth - 1)
        tag_lower = tag.lower()

        if tag_lower in self.ignore_tags:
            self.in_ignore_tag = False

        if tag_lower == "title":
            self.in_title = False

        elif tag_lower == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

        elif tag_lower == "script":
            self.in_script = False
            self.scripts.append({
                "src": self.current_script_attrs.get("src", ""),
                "type": self.current_script_attrs.get("type", "text/javascript"),
                "content": self.current_script_content.strip()
            })
            self.current_script_attrs = {}
            self.current_script_content = ""

        elif tag_lower == "a" and self.current_link is not None:
            self.links.append(self.current_link)
            self.current_link = None

    def handle_data(self, data: str):
        if self.in_title:
            self.title += data
        elif self.in_script:
            self.current_script_content += data
        elif not self.in_ignore_tag:
            self.text_accumulator.append(data)

        if self.current_link is not None and not self.in_ignore_tag:
            self.current_link["text"] += data


class DOMAnalyzer:
    """
    High-level DOM and Structural Inspector for PhishNetra.
    """

    @classmethod
    def analyze_html(cls, html_content: str, base_url: str = "") -> Dict[str, Any]:
        parser = DOMParser(base_url=base_url)
        try:
            parser.feed(html_content)
        except Exception:
            # Tolerant to broken HTML
            pass

        # Close any unclosed form or link
        if parser.current_form is not None:
            parser.forms.append(parser.current_form)
        if parser.current_link is not None:
            parser.links.append(parser.current_link)

        visible_text = " ".join(parser.text_accumulator)
        # Normalize whitespace
        visible_text = re.sub(r"\s+", " ", visible_text).strip()

        # Link metrics
        base_host = ""
        try:
            base_host = urllib.parse.urlsplit(base_url).netloc.lower()
        except Exception:
            pass

        internal_links = 0
        external_links = 0
        suspicious_links = 0
        external_domains: set = set()

        for link in parser.links:
            href = link.get("href", "").strip()
            if not href:
                continue

            href_lower = href.lower()
            if href_lower.startswith(("javascript:", "data:", "vbscript:", "mailto:")):
                suspicious_links += 1
                continue

            try:
                parsed_href = urllib.parse.urlsplit(href)
                target_host = parsed_href.netloc.lower()
                if not target_host or target_host == base_host:
                    internal_links += 1
                else:
                    external_links += 1
                    external_domains.add(target_host)
            except Exception:
                suspicious_links += 1

        # Form metrics
        password_inputs_count = 0
        hidden_inputs_count = 0
        total_inputs_count = 0

        for f in parser.forms:
            for inp in f.get("inputs", []):
                total_inputs_count += 1
                t = inp.get("type", "").lower()
                if t == "password":
                    password_inputs_count += 1
                elif t == "hidden":
                    hidden_inputs_count += 1

        # Script metrics
        external_scripts_count = sum(1 for s in parser.scripts if s.get("src"))

        return {
            "title": parser.title.strip(),
            "visible_text": visible_text,
            "metrics": {
                "nodeCount": parser.node_count,
                "depth": parser.max_depth,
                "formsCount": len(parser.forms),
                "inputsCount": total_inputs_count,
                "passwordInputsCount": password_inputs_count,
                "hiddenInputsCount": hidden_inputs_count,
                "iframesCount": len(parser.iframes),
                "scriptsCount": len(parser.scripts),
                "externalScriptsCount": external_scripts_count,
                "linksCount": len(parser.links),
                "externalLinksCount": external_links,
                "suspiciousLinksCount": suspicious_links
            },
            "forms": parser.forms,
            "iframes": parser.iframes,
            "scripts": parser.scripts,
            "links": parser.links,
            "external_domains": list(external_domains)
        }


dom_analyzer = DOMAnalyzer()
