"""Shared spreadsheet-safe CSV cells; evidence itself remains unchanged."""


def csv_safe(value):
    if isinstance(value,str) and (value[:1] in ('\t','\r','\n') or
            value.lstrip()[:1] in ('=','+','-','@')):
        return "'"+value
    return value
