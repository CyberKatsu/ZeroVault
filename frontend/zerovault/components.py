"""
zerovault.components
====================
Reusable Reflex UI components.
"""

from __future__ import annotations

import reflex as rx

from zerovault.state import ZeroVaultState


# ─── Design tokens ────────────────────────────────────────────────────────────

BG = "#0f172a"        # slate-900
CARD = "#1e293b"      # slate-800
BORDER = "#334155"    # slate-700
TEXT = "#f1f5f9"      # slate-100
MUTED = "#94a3b8"     # slate-400
ACCENT = "#6366f1"    # indigo-500
DANGER = "#ef4444"    # red-500
SUCCESS = "#22c55e"   # green-500


def page_shell(*children) -> rx.Component:
    """Full-page container with dark background."""
    return rx.box(
        *children,
        min_height="100vh",
        background=BG,
        color=TEXT,
        font_family="'Inter', system-ui, sans-serif",
    )


def card(*children, **props) -> rx.Component:
    return rx.box(
        *children,
        background=CARD,
        border=f"1px solid {BORDER}",
        border_radius="12px",
        padding="2rem",
        **props,
    )


def input_field(label: str, **props) -> rx.Component:
    return rx.vstack(
        rx.text(label, color=MUTED, font_size="0.8rem", font_weight="500"),
        rx.input(
            background="#0f172a",
            border=f"1px solid {BORDER}",
            border_radius="8px",
            color=TEXT,
            padding="0.6rem 0.8rem",
            width="100%",
            _focus={"outline": f"2px solid {ACCENT}", "border_color": ACCENT},
            **props,
        ),
        width="100%",
        gap="0.25rem",
        align_items="flex-start",
    )


def primary_button(label: str, **props) -> rx.Component:
    return rx.button(
        label,
        background=ACCENT,
        color="white",
        border_radius="8px",
        padding="0.6rem 1.2rem",
        font_weight="600",
        cursor="pointer",
        _hover={"background": "#4f46e5"},
        _disabled={"opacity": "0.5", "cursor": "not-allowed"},
        **props,
    )


def danger_button(label: str, **props) -> rx.Component:
    return rx.button(
        label,
        background="transparent",
        color=DANGER,
        border=f"1px solid {DANGER}",
        border_radius="6px",
        padding="0.3rem 0.7rem",
        font_size="0.8rem",
        cursor="pointer",
        _hover={"background": "#7f1d1d20"},
        **props,
    )


def ghost_button(label: str, **props) -> rx.Component:
    return rx.button(
        label,
        background="transparent",
        color=MUTED,
        border=f"1px solid {BORDER}",
        border_radius="6px",
        padding="0.3rem 0.7rem",
        font_size="0.8rem",
        cursor="pointer",
        _hover={"color": TEXT, "border_color": TEXT},
        **props,
    )


def alert_box(message: rx.Var, color: str) -> rx.Component:
    return rx.cond(
        message != "",
        rx.box(
            rx.text(message, font_size="0.875rem"),
            background=f"{color}20",
            border=f"1px solid {color}",
            border_radius="8px",
            padding="0.75rem 1rem",
            color=color,
            width="100%",
        ),
        rx.fragment(),
    )


def strength_bar(score: rx.Var, label: rx.Var, color: rx.Var) -> rx.Component:
    """Password strength indicator bar."""
    return rx.cond(
        label != "",
        rx.vstack(
            rx.hstack(
                rx.text("Strength:", color=MUTED, font_size="0.75rem"),
                rx.text(label, color=color, font_size="0.75rem", font_weight="600"),
                gap="0.4rem",
            ),
            rx.hstack(
                *[
                    rx.box(
                        height="4px",
                        flex="1",
                        border_radius="2px",
                        background=rx.cond(
                            score > i,
                            color,
                            BORDER,
                        ),
                    )
                    for i in range(4)
                ],
                width="100%",
                gap="3px",
            ),
            width="100%",
            gap="0.3rem",
        ),
        rx.fragment(),
    )


# ─── Login page ───────────────────────────────────────────────────────────────

def login_page() -> rx.Component:
    return page_shell(
        rx.center(
            rx.vstack(
                # Logo / title
                rx.vstack(
                    rx.text("🔐", font_size="3rem"),
                    rx.heading("ZeroVault", size="7", color=TEXT),
                    rx.text(
                        "Your master password never leaves your device.",
                        color=MUTED,
                        font_size="0.9rem",
                        text_align="center",
                    ),
                    align_items="center",
                    gap="0.5rem",
                ),
                card(
                    rx.vstack(
                        rx.heading("Sign In", size="5", color=TEXT),
                        alert_box(ZeroVaultState.error_message, DANGER),
                        alert_box(ZeroVaultState.success_message, SUCCESS),
                        input_field(
                            "Username",
                            placeholder="your_username",
                            value=ZeroVaultState.form_username,
                            on_change=ZeroVaultState.set_form_username,
                        ),
                        input_field(
                            "Master Password",
                            placeholder="Your master password",
                            type="password",
                            value=ZeroVaultState.form_master_password,
                            on_change=ZeroVaultState.set_form_master_password,
                        ),
                        primary_button(
                            "Sign In",
                            width="100%",
                            on_click=ZeroVaultState.login,
                            is_loading=ZeroVaultState.is_loading,
                            disabled=ZeroVaultState.is_loading,
                        ),
                        rx.hstack(
                            rx.text("Don't have an account?", color=MUTED, font_size="0.85rem"),
                            rx.button(
                                "Create one",
                                variant="ghost",
                                color=ACCENT,
                                font_size="0.85rem",
                                cursor="pointer",
                                on_click=ZeroVaultState.go_to_register,
                                padding="10",
                                background="transparent",
                                border="none",
                                _hover={"color": "#818cf8"},
                            ),
                            gap="0.4rem",
                            justify_content="center",
                        ),
                        gap="1rem",
                        width="100%",
                    ),
                    width="380px",
                ),
                gap="1.5rem",
                align_items="center",
            ),
            min_height="100vh",
        )
    )


# ─── Register page ────────────────────────────────────────────────────────────

def register_page() -> rx.Component:
    return page_shell(
        rx.center(
            rx.vstack(
                rx.vstack(
                    rx.text("🔐", font_size="3rem"),
                    rx.heading("ZeroVault", size="7", color=TEXT),
                    rx.text(
                        "Zero-knowledge password manager",
                        color=MUTED,
                        font_size="0.9rem",
                    ),
                    align_items="center",
                    gap="0.5rem",
                ),
                card(
                    rx.vstack(
                        rx.heading("Create Account", size="5", color=TEXT),
                        rx.box(
                            rx.text(
                                "⚠️  Choose your master password carefully. It is the only key to your vault "
                                "and cannot be recovered if lost.",
                                font_size="0.8rem",
                                color="#fbbf24",
                            ),
                            background="#78350f20",
                            border="1px solid #78350f",
                            border_radius="8px",
                            padding="0.75rem",
                        ),
                        alert_box(ZeroVaultState.error_message, DANGER),
                        input_field(
                            "Username",
                            placeholder="your_username",
                            value=ZeroVaultState.form_username,
                            on_change=ZeroVaultState.set_form_username,
                        ),
                        input_field(
                            "Master Password  (≥ 12 characters)",
                            placeholder="A strong passphrase",
                            type="password",
                            value=ZeroVaultState.form_master_password,
                            on_change=ZeroVaultState.set_form_master_password,
                        ),
                        input_field(
                            "Confirm Master Password",
                            placeholder="Repeat your master password",
                            type="password",
                            value=ZeroVaultState.form_confirm_password,
                            on_change=ZeroVaultState.set_form_confirm_password,
                        ),
                        primary_button(
                            "Create Account",
                            width="100%",
                            on_click=ZeroVaultState.register,
                            is_loading=ZeroVaultState.is_loading,
                            disabled=ZeroVaultState.is_loading,
                        ),
                        rx.hstack(
                            rx.text("Already have an account?", color=MUTED, font_size="0.85rem"),
                            rx.button(
                                "Sign in",
                                variant="ghost",
                                color=ACCENT,
                                font_size="0.85rem",
                                cursor="pointer",
                                on_click=ZeroVaultState.go_to_login,
                                padding="0",
                                background="transparent",
                                border="none",
                                _hover={"color": "#818cf8"},
                            ),
                            gap="0.4rem",
                            justify_content="center",
                        ),
                        gap="1rem",
                        width="100%",
                    ),
                    width="420px",
                ),
                gap="1.5rem",
                align_items="center",
            ),
            min_height="100vh",
        )
    )


# ─── Vault entry card ─────────────────────────────────────────────────────────

def entry_card(entry: dict) -> rx.Component:
    entry_id = entry["id"]
    is_revealed = ZeroVaultState.revealed_ids.contains(entry_id)

    return rx.box(
        rx.vstack(
            # Header row: site + delete
            rx.hstack(
                rx.vstack(
                    rx.text(
                        entry["site"],
                        font_weight="600",
                        color=TEXT,
                        font_size="0.95rem",
                    ),
                    rx.text(
                        entry["username"],
                        color=MUTED,
                        font_size="0.8rem",
                    ),
                    gap="0.1rem",
                    align_items="flex-start",
                ),
                rx.spacer(),
                danger_button(
                    "Delete",
                    on_click=ZeroVaultState.delete_vault_entry(entry_id),
                ),
                width="100%",
                align_items="center",
            ),
            # Password row
            rx.hstack(
                rx.text(
                    rx.cond(is_revealed, entry["password"], "••••••••••••"),
                    font_family="monospace",
                    color=rx.cond(is_revealed, "#a5f3fc", MUTED),
                    font_size="0.875rem",
                ),
                rx.spacer(),
                ghost_button(
                    rx.cond(is_revealed, "Hide", "Reveal"),
                    on_click=ZeroVaultState.toggle_reveal_password(entry_id),
                ),
                width="100%",
                align_items="center",
            ),
            # Notes
            rx.cond(
                entry["notes"] != "",
                rx.text(
                    entry["notes"],
                    color=MUTED,
                    font_size="0.8rem",
                    font_style="italic",
                ),
                rx.fragment(),
            ),
            # Timestamp
            rx.text(
                entry["created_at"],
                color="#475569",
                font_size="0.7rem",
            ),
            gap="0.6rem",
            align_items="flex_start",
            width="100%",
        ),
        background=CARD,
        border=f"1px solid {BORDER}",
        border_radius="10px",
        padding="1rem 1.2rem",
        width="100%",
        _hover={"border_color": "#475569"},
        transition="border-color 0.15s",
    )


# ─── Add entry form ────────────────────────────────────────────────────────────

def add_entry_form() -> rx.Component:
    return card(
        rx.vstack(
            rx.heading("Add Entry", size="4", color=TEXT),
            alert_box(ZeroVaultState.error_message, DANGER),
            alert_box(ZeroVaultState.success_message, SUCCESS),
            rx.grid(
                input_field(
                    "Website / Service *",
                    placeholder="https://github.com",
                    value=ZeroVaultState.new_site,
                    on_change=ZeroVaultState.set_new_site,
                ),
                input_field(
                    "Username / Email",
                    placeholder="alice@example.com",
                    value=ZeroVaultState.new_username,
                    on_change=ZeroVaultState.set_new_username,
                ),
                columns="2",
                gap="1rem",
                width="100%",
            ),
            rx.vstack(
                input_field(
                    "Password *",
                    placeholder="Enter or paste password",
                    type="text",   # Show plaintext in add form — user is adding
                    value=ZeroVaultState.new_password,
                    on_change=ZeroVaultState.update_new_password,
                ),
                strength_bar(
                    ZeroVaultState.password_strength_score,
                    ZeroVaultState.password_strength_label,
                    ZeroVaultState.password_strength_color,
                ),
                width="100%",
                gap="0.4rem",
            ),
            input_field(
                "Notes",
                placeholder="Optional notes",
                value=ZeroVaultState.new_notes,
                on_change=ZeroVaultState.set_new_notes,
            ),
            primary_button(
                "Encrypt & Save",
                on_click=ZeroVaultState.add_vault_entry,
                is_loading=ZeroVaultState.is_loading,
                disabled=ZeroVaultState.is_loading,
            ),
            gap="1rem",
            width="100%",
        ),
        width="100%",
    )


# ─── Vault page ───────────────────────────────────────────────────────────────

def vault_page() -> rx.Component:
    return page_shell(
        rx.vstack(
            # Navbar
            rx.hstack(
                rx.hstack(
                    rx.text("🔐", font_size="1.4rem"),
                    rx.heading("ZeroVault", size="5", color=TEXT),
                    gap="0.5rem",
                    align_items="center",
                ),
                rx.spacer(),
                rx.hstack(
                    rx.text(
                        ZeroVaultState.current_username,
                        color=MUTED,
                        font_size="0.875rem",
                    ),
                    danger_button("Logout", on_click=ZeroVaultState.logout),
                    gap="1rem",
                    align_items="center",
                ),
                width="100%",
                padding="1rem 2rem",
                background=CARD,
                border_bottom=f"1px solid {BORDER}",
                align_items="center",
            ),
            # Zero-knowledge banner
            rx.box(
                rx.text(
                    "🛡️  Zero-knowledge mode active — vault entries are encrypted in "
                    "memory before leaving your session. The server stores only ciphertext.",
                    font_size="0.8rem",
                    color="#86efac",
                    text_align="center",
                ),
                background="#14532d20",
                border_bottom="1px solid #14532d",
                padding="0.5rem 2rem",
                width="100%",
            ),
            # Main content
            rx.hstack(
                # Left: Add form
                rx.box(
                    add_entry_form(),
                    width="380px",
                    flex_shrink="0",
                ),
                # Right: Vault list
                rx.vstack(
                    rx.hstack(
                        rx.heading(
                            "Your Vault",
                            size="4",
                            color=TEXT,
                        ),
                        rx.text(
                            f"{ZeroVaultState.vault_entries.length()} entries",
                            color=MUTED,
                            font_size="0.875rem",
                        ),
                        align_items="center",
                        gap="1rem",
                    ),
                    rx.cond(
                        ZeroVaultState.vault_entries.length() == 0,
                        rx.center(
                            rx.vstack(
                                rx.text("🔒", font_size="3rem"),
                                rx.text("No entries yet.", color=MUTED),
                                rx.text(
                                    "Add a site on the left to get started.",
                                    color="#475569",
                                    font_size="0.85rem",
                                ),
                                align_items="center",
                                gap="0.5rem",
                            ),
                            padding="3rem",
                            width="100%",
                        ),
                        rx.vstack(
                            rx.foreach(
                                ZeroVaultState.vault_entries,
                                entry_card,
                            ),
                            width="100%",
                            gap="0.75rem",
                        ),
                    ),
                    width="100%",
                    gap="1rem",
                    align_items="flex-start",
                ),
                gap="2rem",
                padding="2rem",
                align_items="flex-start",
                width="100%",
            ),
            gap="0",
            width="100%",
        )
    )
