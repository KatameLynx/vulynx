from urllib.parse import urljoin


def extract_form_fields(page_url, form):
    action = form.get("action") or page_url
    action_url = urljoin(page_url, action)
    method = (form.get("method") or "get").lower()

    fields = []
    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        if not name:
            continue
        field_type = inp.get("type", "text").lower() if inp.name == "input" else "text"
        value = inp.get("value", "")
        fields.append({"name": name, "type": field_type, "value": value})

    return action_url, method, fields


def submit_form(session, action_url, method, data, timeout=10):
    if method == "post":
        return session.post(action_url, data=data, timeout=timeout)
    return session.get(action_url, params=data, timeout=timeout)


def has_csrf_token(fields):
    csrf_hints = ("csrf", "xsrf", "token", "authenticity", "nonce")
    for f in fields:
        if f["type"] == "hidden" and any(h in f["name"].lower() for h in csrf_hints):
            return True
    return False