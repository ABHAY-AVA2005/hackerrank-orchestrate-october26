"""
Authorization and request intent classifier.
Distinguishes genuine right-to-be-forgotten / deletion requests from
routine data subject access requests, contact info updates, or marketing opt-outs.

Strategy:
  1. Check explicit NON_DELETION patterns first (fast path out).
  2. Check positive DELETION keywords (multilingual).
  3. If still ambiguous -> call Gemini API as final arbiter.
  4. Cache all results so re-runs never re-call the API.
"""
from __future__ import annotations
import os
from typing import Tuple, Optional

# ---------------------------------------------------------------------------
# Hard-coded pattern lists
# ---------------------------------------------------------------------------

NON_DELETION_PATTERNS = [
    # English
    'leave the account active', 'not asking for deletion', 'keep the account as it is',
    'do not close the account', 'without removing any of my records', 'marketing lists only',
    'not a request to erase', 'leave my profile', 'continue using the service',
    "don't delete", 'leave the account open', 'keep my account',
    'access my data', 'download my data', 'export my data', 'data portability',
    'opt out of marketing', 'unsubscribe', 'update my settings', 'correct my',
    'data access request', 'subject access request',
    # French
    'acc\u00e8s \u00e0 mes donn\u00e9es', 'rectification',
    # Spanish
    'acceder a mis datos', 'actualizar mis datos',
]

DELETION_KEYWORDS = [
    # English
    'delete', 'deleting', 'deletion', 'remove my', 'erase', 'close my account',
    'close this account', 'close the account', 'right to be forgotten', 'gdpr',
    'forget me', 'wipe', 'purge', 'account closure', 'permanently remove',
    'remove all', 'remove the profile', 'remove that', 'remove personal',
    'data erasure', 'erasure request', 'account deleted', 'account removal',
    'remove records', 'remove data', 'remove my information', 'remove my details',
    'permanently delete', 'erased', 'closed', 'i want it closed', 'please remove',
    'get rid of', 'already been removed', 'profile is gone', 'profile has been removed',
    'request failed', 'left behind', 'tied to the old',
    # French
    'supprimer', 'suppression', 'effacer', 'cl\u00f4turer', "droit \u00e0 l'oubli",
    'suppression d\u00e9finitive', 'demande de suppression', 'supprimer le compte',
    # Spanish
    'eliminar', 'borrar', 'cerrar mi cuenta', 'eliminaci\u00f3n', 'suprimir',
    'borrar mi cuenta', 'eliminar mi cuenta', 'eliminar mis datos',
    # German
    'l\u00f6schen', 'l\u00f6schung', 'konto schlie\u00dfen', 'datenl\u00f6schung',
    # Japanese
    '\u524a\u9664', '\u30a2\u30ab\u30a6\u30f3\u30c8\u3092\u524a\u9664', '\u9000\u4f1a', '\u6d88\u53bb',
    # Portuguese
    'apagar', 'excluir', 'deletar', 'remover minha conta',
    # Arabic
    '\u062d\u0630\u0641', '\u0625\u0632\u0627\u0644\u0629',
    # Chinese
    '\u5220\u9664', '\u6ce8\u9500',
    # Italian
    'cancellare', 'eliminare',
    # Dutch
    'verwijderen', 'account sluiten',
]


# ---------------------------------------------------------------------------
# Gemini-based fallback (lazy-loaded, cached)
# ---------------------------------------------------------------------------

_gemini_cache: dict = {}
_gemini_model = None
_gemini_available = None   # None = not yet checked


def _load_env_vars():
    """Manually parse .env file walking up from this file's directory."""
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        candidate = os.path.join(here, '.env')
        if os.path.exists(candidate):
            with open(candidate, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        k, v = k.strip(), v.strip()
                        if k not in os.environ:
                            os.environ[k] = v
            return
        here = os.path.dirname(here)


def _get_gemini_model():
    global _gemini_model, _gemini_available
    if _gemini_available is False:
        return None
    if _gemini_model is not None:
        return _gemini_model
    try:
        _load_env_vars()
        import google.generativeai as genai
        api_key = os.environ.get('GEMINI_API_KEY', '')
        if not api_key or api_key == 'your_gemini_api_key_here':
            _gemini_available = False
            return None
        genai.configure(api_key=api_key)
        _gemini_model = genai.GenerativeModel('gemini-2.5-flash')
        _gemini_available = True
        return _gemini_model
    except Exception:
        _gemini_available = False
        return None


_GEMINI_PROMPT = (
    "You are classifying a customer request to a company.\n"
    "Answer with EXACTLY one word: DELETION or NOT_APPLICABLE.\n\n"
    "DELETION: person wants their account/personal data permanently deleted, erased, removed, or forgotten.\n"
    "NOT_APPLICABLE: person wants data access, export, correction, opt-out, account help, or anything other than deletion.\n\n"
    "Request:\n{text}\n\nAnswer:"
)


def _classify_with_gemini(text: str) -> Optional[bool]:
    """Returns True=deletion, False=not_applicable, None=unavailable."""
    cache_key = text.strip().lower()[:500]
    if cache_key in _gemini_cache:
        return _gemini_cache[cache_key]
    model = _get_gemini_model()
    if model is None:
        return None
    try:
        resp = model.generate_content(_GEMINI_PROMPT.format(text=text[:2000]))
        answer = resp.text.strip().upper()
        result = 'DELETION' in answer and 'NOT_APPLICABLE' not in answer
        _gemini_cache[cache_key] = result
        return result
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AuthorizationChecker:

    @classmethod
    def is_deletion_request(cls, request_text: str) -> Tuple[bool, str]:
        """
        Returns: (is_deletion, reason)

        Flow:
          1. NON_DELETION pattern match  -> False  (fast exit)
          2. DELETION keyword match      -> True   (fast exit)
          3. Gemini API classification   -> True/False
          4. Default                     -> False  (safe: NOT_APPLICABLE)
        """
        if not request_text or not request_text.strip():
            return False, 'Empty request — not a deletion request'

        lower = request_text.lower()

        for pattern in NON_DELETION_PATTERNS:
            if pattern in lower:
                return False, f"Non-deletion: '{pattern}'"

        for kw in DELETION_KEYWORDS:
            if kw in lower:
                return True, f"Deletion keyword: '{kw}'"

        gemini_result = _classify_with_gemini(request_text)
        if gemini_result is True:
            return True, 'Deletion confirmed by Gemini'
        if gemini_result is False:
            return False, 'Not-deletion determined by Gemini'

        # No signal — safe default: NOT_APPLICABLE
        return False, 'No deletion intent detected'

