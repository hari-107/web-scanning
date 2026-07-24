from django import template

register = template.Library()


@register.filter
def get_item(mapping, key):
    """Look up ``mapping[key]`` in templates (dicts don't support [] there)."""
    if hasattr(mapping, "get"):
        return mapping.get(key, 0)
    return 0
