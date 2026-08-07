"""
Firebase Authentication
"""

import anvil.js

proxy_auth = None
auth = None


def init(app, persistence):
    global proxy_auth
    global auth
    proxy_auth = anvil.js.import_from(
        "https://www.gstatic.com/firebasejs/10.4.0/firebase-auth.js"
    )
    auth = proxy_auth.getAuth(app)
    if persistence == "local_persistence":
        proxy_auth.setPersistence(auth, proxy_auth.indexedDBLocalPersistence)
    elif persistence == "session_persistence":
        proxy_auth.setPersistence(auth, proxy_auth.browserSessionPersistence)
    else:
        proxy_auth.setPersistence(auth, proxy_auth.browserLocalPersistence)


"""Main Methods"""


def get_user():
    try:
        return FireUser(anvil.js.await_promise(auth.currentUser))
    except Exception as e:
        print("Warning user not found ", e)
        return None


def logout_user():
    anvil.js.await_promise(proxy_auth.signOut(auth))


def signup_with_email(email, password):
    userCredential = anvil.js.await_promise(
        proxy_auth.createUserWithEmailAndPassword(auth, email, password)
    )
    return FireUser(userCredential.user)


def sign_in_with_email(email, password):
    """Checks if a user is already logged in, if not attempts login flow"""
    userCredential = anvil.js.await_promise(
        proxy_auth.signInWithEmailAndPassword(auth, email, password)
    )
    return FireUser(userCredential.user)


def sign_in_with_token(token):
    """Login with a custom token generated with the firebase sdk"""
    userCredential = anvil.js.await_promise(
        proxy_auth.signInWithCustomToken(auth, token)
    )
    return FireUser(userCredential.user)


def login_with_anvil(user_claims=[]):
    import anvil.server

    token = anvil.server.call("_fs_get_anvil_firestore_auth_token", user_claims)
    return sign_in_with_token(token)


# onAuthStateChanged helper for Anvil + Firebase Auth
_auth_listeners = {}


def on_auth_state_changed(py_callback):
    """
    Register a Python callable to be called on Firebase auth state changes.

    - py_callback: callable taking one argument: a `FireUser` instance or `None`.
    - Returns: a Python callable `unsubscribe()` to stop listening.

    Note: `init(app, persistence)` must have been called first to initialize `auth`.
    """
    if auth is None:
        raise RuntimeError(
            "Auth is not initialized. Call `init(app, persistence)` first."
        )

    # Internal proxy callback invoked from JS with the proxied JS user object (or null).
    def _proxy_cb(proxy_user):
        try:
            if proxy_user is None:
                py_callback(None)
            else:
                py_callback(FireUser(proxy_user))
        except Exception as e:
            # Keep errors visible but don't let them crash the JS callback
            print("onAuthStateChanged callback error:", e)

    # Wrap Python function so JS can call it
    js_cb = anvil.js.callable(_proxy_cb)

    # Register with Firebase; returns an unsubscribe function (JS function)
    unsubscribe_fn = proxy_auth.onAuthStateChanged(auth, js_cb)

    # Keep references so the JS callback isn't GC'd while registered
    key = id(js_cb)
    _auth_listeners[key] = (js_cb, unsubscribe_fn)

    # Return a Python callable to unsubscribe and cleanup references
    def unsubscribe():
        try:
            # Call the JS unsubscribe function
            unsubscribe_fn()
        except Exception as e:
            print("Failed to unsubscribe from onAuthStateChanged:", e)
        finally:
            _auth_listeners.pop(key, None)

    return unsubscribe


"""Wraps a Firestore proxy user"""


class FireUser:
    def __init__(self, proxy_user):
        if proxy_user is None:
            raise ValueError("Unkown Firebase User")
        self.proxy_user = proxy_user

    @property
    def uid(self):
        return self.proxy_user.uid

    @property
    def email(self):
        return self.proxy_user.email

    def logout(self):
        logout_user()

    def get_id_token(self, force_refresh=False):
        from .helper import utility

        return utility.from_proxy(
            anvil.js.await_promise(self.proxy_user.getIdToken(force_refresh))
        )

    def get_id_token_result(self, force_refresh=False):
        from .helper import utility

        return utility.from_proxy(
            anvil.js.await_promise(self.proxy_user.getIdTokenResult(force_refresh))
        )

    def __repr__(self):
        try:
            return f"<FireUser {self.uid} {self.email}>"
        except Exception as e:
            print(e)
            return "unknown firebase user"
