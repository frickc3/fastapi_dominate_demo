"""
HTML views generated with dominate (pure Python DOM), styled with **UnoCSS**
through the official runtime CDN build (Wind3 preset, injected at runtime).

Every page shares ``page()`` (navbar, flash area) and every mutating form
embeds a hidden CSRF field from ``csrf_field()``.
"""

from dominate import document
from dominate import tags as t

UNO_RUNTIME = "https://cdn.jsdelivr.net/npm/@unocss/runtime/uno.global.js"
UNO_RESET = "https://cdn.jsdelivr.net/npm/@unocss/reset/normalize.min.css"


def csrf_field(token: str):
    return t.input_(type="hidden", name="_csrf", value=token)


# ------------------------------------------------------------ page shell ----

def page(title: str, content, flashes=None, user=None, active: str = "",
         csrf_token: str = "") -> str:
    """Full HTML document: navbar + flash area + content."""
    doc = document(title=title)
    with doc.head:
        t.meta(charset="utf-8")
        t.meta(name="viewport", content="width=device-width, initial-scale=1")
        t.link(rel="stylesheet", href=UNO_RESET)
        t.style("[un-cloak]{display:none}"
                "body{min-height:100vh;font-family:ui-sans-serif,system-ui,"
                "sans-serif;background-color:#f5f6fa;margin:0}")
    with doc:
        with t.div(cls="flex flex-col min-h-screen", **{"un-cloak": ""}):
            # ---------------- navbar
            with t.nav(cls="bg-gray-900 text-gray-100"):
                with t.div(cls="max-w-4xl mx-auto w-full px-4 py-3 flex items-center gap-4"):
                    with t.a(href="/", cls="font-bold text-lg flex items-center gap-2"):
                        t.span("⚡ Fast", cls="text-emerald-300")
                        t.span("Site")
                    with t.ul(cls="ml-auto flex items-center gap-4 text-sm list-none"):
                        t.li(t.a("Home", href="/",
                                 cls="hover:text-emerald-300" +
                                 (" text-emerald-300" if active == "home" else "")))
                        if user:
                            t.li(t.a("My notes", href="/notes",
                                     cls="hover:text-emerald-300" +
                                     (" text-emerald-300" if active == "notes" else "")))
                            #t.li(t.span(user.username, cls="text-gray-400"))
                            with t.li():
                                with t.form(action="/logout", method="post",
                                            cls="inline", id="logout-form"):
                                    csrf_field(csrf_token)
                                    t.button("Logout",
                                             cls="px-3 py-1.5 rounded-lg bg-gray-700 "
                                                 "hover:bg-gray-600 cursor-pointer",
                                             type_="submit")
                        else:
                            t.li(t.a("Login", href="/login",
                                     cls="hover:text-emerald-300" +
                                     (" text-emerald-300" if active == "login" else "")))
                            t.li(t.a("Register", href="/register",
                                     cls="px-3 py-1.5 rounded-lg bg-emerald-600 "
                                         "hover:bg-emerald-500",
                                     **{"data-testid": "nav-register"}))

            # ---------------- flash messages
            with t.main(cls="flex-1 w-full") as main_area:
                with t.div(cls="max-w-4xl mx-auto w-full px-4") as main_wrap:
                    if flashes:
                        for category, message in flashes:
                            color = {
                                "success": "bg-emerald-50 text-emerald-800 border-emerald-300",
                                "danger": "bg-red-50 text-red-800 border-red-300",
                                "warning": "bg-yellow-50 text-yellow-800 border-yellow-300",
                                "info": "bg-blue-50 text-blue-800 border-blue-300",
                            }.get(category, "bg-blue-50 text-blue-800 border-blue-300")
                            t.div(message,
                                  cls=f"mt-4 px-4 py-3 rounded-lg border {color}",
                                  **{"data-testid": f"flash-{category}"})
                    main_wrap.add(content)

            # ---------------- footer
            with t.footer(cls="bg-gray-900 text-gray-400 text-sm"):
                with t.div(cls="max-w-4xl mx-auto w-full px-4 py-4 flex justify-between"):
                    t.span("FastAPI · dominate · UnoCSS · fastlite")
                    t.span("SQLCipher AE-256 at rest · Argon2 · CSRF")
        t.script(src=UNO_RUNTIME)
    return doc.render(pretty=False)


# ---------------------------------------------------------------- pages -----

def index_page(user, csrf_token, flashes=None) -> str:
    with t.div(cls="py-16 text-center") as hero:
        t.h1("Login, logout, register — on an encrypted database",
             cls="text-4xl font-bold mb-4")
        t.p("FastAPI + dominate + UnoCSS + fastlite on SQLCipher. Signed "
            "HttpOnly session cookies, CSRF tokens, strict CSP and Argon2 "
            "password hashing.",
            cls="text-lg text-gray-500 max-w-xl mx-auto mb-6")
        if user:
            hero.add(t.a("Open my notes →", href="/notes",
                         cls="inline-block px-6 py-3 rounded-xl bg-emerald-600 "
                             "text-white text-lg hover:bg-emerald-500"))
        else:
            hero.add(t.span(
                t.a("Create an account", href="/register",
                    cls="px-6 py-3 rounded-xl bg-emerald-600 text-white text-lg "
                        "hover:bg-emerald-500"),
                " ",
                t.a("Log in", href="/login",
                    cls="px-6 py-3 rounded-xl bg-white border text-lg hover:bg-gray-50"),
            ))
    return page("FastSite", hero, flashes=flashes, user=user,
                csrf_token=csrf_token, active="home")


def register_form(csrf_token, error=None, values=None) -> str:
    values = values or {}
    with t.div(cls="py-10 flex justify-center") as out:
        with t.div(cls="w-full max-w-md"):
            with t.div(cls="bg-white rounded-2xl shadow-md p-8", un_cloak=""):
                t.h5("Create an account", cls="text-2xl font-bold text-center mb-6")
                if error:
                    t.div(error, cls="mb-4 px-4 py-3 rounded-lg border "
                                     "bg-red-50 text-red-800 border-red-300")
                with t.form(action="/register", method="post", id="register-form"):
                    csrf_field(csrf_token)
                    for label, name, itype in (
                        ("Email", "email", "email"),
                        #("Username (3–24 letters, digits, . _ -)", "username", "text"),
                        ("Password (min 10 chars)", "password", "password"),
                        ("Repeat password", "password_again", "password"),
                    ):
                        with t.div(cls="mb-4"):
                            t.label(label, cls="block text-sm font-medium mb-1",
                                    **{"for": f"reg_{name}"})
                            t.input_(type="text" if name == "username" else itype,
                                     id=f"reg_{name}", name=name,
                                     value=values.get(name, ""),
                                     minlength="10" if name.startswith("password") else None,
                                     cls="w-full px-3 py-2 rounded-lg border border-gray-300 "
                                         "focus:outline-none focus:ring-2 focus:ring-emerald-500",
                                     required=None)
                    t.button("Register",
                             cls="w-full px-4 py-2.5 rounded-xl bg-emerald-600 text-white "
                                 "font-semibold hover:bg-emerald-500 cursor-pointer",
                             type_="submit")
                t.p("Already registered? ", t.a("Log in", href="/login",
                                                cls="text-emerald-700 hover:underline"),
                    cls="text-center text-sm text-gray-500 mt-4 mb-0")
    return page("Register · FastSite", out, user=None, active="register")


def login_form(csrf_token, error=None, next_url: str = "") -> str:
    with t.div(cls="py-10 flex justify-center") as out:
        with t.div(cls="w-full max-w-sm"):
            with t.div(cls="bg-white rounded-2xl shadow-md p-8"):
                t.h5("Log in", cls="text-2xl font-bold text-center mb-6")
                if error:
                    t.div(error, cls="mb-4 px-4 py-3 rounded-lg border "
                                     "bg-red-50 text-red-800 border-red-300")
                with t.form(action="/login", method="post", id="login-form"):
                    csrf_field(csrf_token)
                    if next_url:
                        t.input_(type="hidden", name="next", value=next_url)
                    with t.div(cls="mb-4"):
                        t.label("Email", cls="block text-sm font-medium mb-1",
                                **{"for": "login_email"})
                        t.input_(type="email", id="login_email", name="email",
                                 cls="w-full px-3 py-2 rounded-lg border border-gray-300 "
                                     "focus:outline-none focus:ring-2 focus:ring-emerald-500",
                                 required=None)
                    with t.div(cls="mb-4"):
                        t.label("Password", cls="block text-sm font-medium mb-1",
                                **{"for": "login_password"})
                        t.input_(type="password", id="login_password", name="password",
                                 cls="w-full px-3 py-2 rounded-lg border border-gray-300 "
                                     "focus:outline-none focus:ring-2 focus:ring-emerald-500",
                                 required=None)
                    t.button("Log in",
                             cls="w-full px-4 py-2.5 rounded-xl bg-emerald-600 text-white "
                                 "font-semibold hover:bg-emerald-500 cursor-pointer",
                             type_="submit")
                t.p("No account? ", t.a("Register", href="/register",
                                        cls="text-emerald-700 hover:underline"),
                    cls="text-center text-sm text-gray-500 mt-4 mb-0")
    return page("Login · FastSite", out, user=None, active="login")


def notes_page(user, notes, csrf_token, error=None, flashes=None) -> str:
    with t.div(cls="py-8 flex flex-col gap-6") as out:
        # ---------- add-note card
        with t.div(cls="bg-white rounded-2xl shadow-md p-6"):
            t.h5("New note", cls="text-xl font-bold mb-3")
            with t.form(action="/notes", method="post", id="note-form"):
                csrf_field(csrf_token)
                t.textarea(name="body", maxlength="2000",
                           placeholder="Write something private…",
                           cls="w-full h-28 px-3 py-2 rounded-lg border border-gray-300 "
                               "focus:outline-none focus:ring-2 focus:ring-emerald-500")
                t.button("Save note", type_="submit",
                         cls="mt-3 px-5 py-2 rounded-xl bg-emerald-600 text-white "
                             "font-semibold hover:bg-emerald-500 cursor-pointer")
            if error:
                t.div(error, cls="mt-4 px-4 py-3 rounded-lg border "
                                 "bg-red-50 text-red-800 border-red-300")
        # ---------- note list
        with t.div(cls="bg-white rounded-2xl shadow-md p-6"):
            t.h5("Your notes ",
                 t.span(f"({len(notes)})", cls="text-gray-400 font-normal"),
                 cls="text-xl font-bold mb-3")
            if notes:
                with t.ul(cls="flex flex-col gap-2"):
                    for note in notes:
                        with t.li(cls="flex items-center justify-between gap-4 px-4 py-3 "
                                      "bg-gray-50 rounded-lg",
                                  **{"data-testid": "note"}):
                            t.span(note.body, cls="break-all")
                            with t.form(action="/notes/delete", method="post",
                                        cls="shrink-0"):
                                csrf_field(csrf_token)
                                t.input_(type="hidden", name="note_id", value=str(note.id))
                                t.button("Delete",
                                         cls="px-3 py-1 rounded-lg border border-red-300 "
                                             "text-red-600 hover:bg-red-50 cursor-pointer",
                                         type_="submit")
            else:
                t.p("No notes yet — the first one will be stored encrypted at rest.",
                    cls="text-gray-500")
    return page("My notes · FastSite", out, flashes=flashes, user=user,
                active="notes", csrf_token=csrf_token)


def not_found_page(path: str) -> str:
    with t.div(cls="py-24 text-center") as out:
        t.h1("404", cls="text-6xl font-bold mb-4")
        t.p(f"No page at {path}", cls="text-gray-500 mb-6")
        t.a("Back home", href="/",
            cls="px-5 py-2.5 rounded-xl bg-white border hover:bg-gray-50")
    return page("Not found · FastSite", out, user=None)
