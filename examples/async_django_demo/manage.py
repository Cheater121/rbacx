#!/usr/bin/env python
"""Django management script for the async RBACX demo."""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "async_rbacx_demo.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Install it with: pip install rbacx[adapters-drf]"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
