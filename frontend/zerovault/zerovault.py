"""
zerovault/zerovault.py
======================
Reflex application entry point.

Page routing is driven by ZeroVaultState.page rather than Reflex's URL-based
routing.  This avoids exposing /vault as an accessible URL without auth
and keeps the entire app as a single-page application.
"""

import reflex as rx

from zerovault.components import login_page, register_page, vault_page
from zerovault.state import ZeroVaultState


def index() -> rx.Component:
    """
    Root page: render the correct sub-page based on State.page.

    Conditional rendering instead of separate routes prevents direct URL
    access to authenticated pages.
    """
    return rx.cond(
        ZeroVaultState.on_vault_page,
        vault_page(),
        rx.cond(
            ZeroVaultState.on_register_page,
            register_page(),
            login_page(),
        ),
    )


app = rx.App(
    style={
        "background": "#0f172a",
        "font_family": "'Inter', system-ui, sans-serif",
        "*": {"box_sizing": "border-box"},
    },
)

app.add_page(index, route="/", title="ZeroVault — Zero-Knowledge Password Manager")
